// Copyright (c) 2019 Ericsson Eurolab Deutschland GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"fmt"
	"net"
	"syscall"

 
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	persistapi "github.com/kata-containers/runtime/virtcontainers/persist/api"
	log "github.com/sirupsen/logrus"

	"github.com/kata-containers/runtime/virtcontainers/store"
	"github.com/kata-containers/runtime/virtcontainers/types"
	"github.com/kata-containers/runtime/virtcontainers/utils"
	"github.com/kata-containers/runtime/virtcontainers/device/config"
	
	govmmIch "github.com/kata-containers/runtime/virtcontainers/pkg/intel/govmm/ich"
	
)

//
// Constants and type definitions related to cloud hypervisor
//

type ichState uint8

const (
	ichNotReady ichState = iota
	ichReady
)

const (
	ichTimeout            = 10
	ichSocket             = "ich.sock"
	vfsdSocket            = "virtiofsd.sock"
	apiSocket             = "cloud-hypervisor.9166"
	ichStopSandboxTimeout = 15
)

// the info struct goes to disk as hypervisor.json!

type CloudHypervisorInfo struct {
	PID int
}

//
// cloud hypervisor state
//
type CloudHypervisorState struct {
	sync.RWMutex
	state ichState
	PID int
	VirtiofsdPid int
	UUID string
}

func (s *CloudHypervisorState) set(state ichState) {
	s.Lock()
	defer s.Unlock()

	s.state = state
}

//
// cloud hypervisor 
//
type cloudHypervisor struct {
	id         string 
	state      CloudHypervisorState
	info       CloudHypervisorInfo
	ichd       *exec.Cmd
	store      *store.VCStore
	config     HypervisorConfig
	ctx        context.Context
	socketPath string
	ichConfig  govmmIch.Config
	arch 	   ichArchBase
}

var ichKernelParams = []Param{
	
	{"root", "/dev/vda1"},
	{"panic", "1"},
	{"init", "/usr/lib/systemd/systemd"},
	{"kvm-intel.nested", "1"},
	{"no_timer_check" , ""},
	{"noreplace-smp", ""},
	{"page_alloc.shuffle", "1"},

}

var ichDebugKernelParams = []Param{
	
	{"console", "ttyS0,115200n8"},
	{"systemd.log_level","debug"},
	{"initcall_debug",""},
	
}

//#####################################
//
// hypervisor interface implementation
//
//#####################################

func (ich *cloudHypervisor) createSandbox(ctx context.Context, id string, networkNS NetworkNamespace, hypervisorConfig *HypervisorConfig, vcStore *store.VCStore) error {
	ich.ctx = ctx

	span, _ := ich.trace("createSandbox")
	defer span.Finish()
	
	err := hypervisorConfig.valid()
	if err != nil {
		return err
	}

	ich.id = id
	ich.store = vcStore
	ich.config = *hypervisorConfig
	ich.arch = newIchArch(ich.config)
	ich.state.set(ichNotReady)
	 
	socketPath, err := ich.vsockSocketPath(id)
	if err != nil {
			ich.Logger().Info("Invalid socket path for cloud-hypervisor")
			return nil
	}
	ich.socketPath = socketPath
	
	ich.Logger().WithField("function", "createSandbox").Info("creating Sandbox")

	// TODO cross-check this with qemu procedures

	// No need to return an error from there since there might be nothing
	// to fetch if this is the first time the hypervisor is created.
	if err := ich.store.Load(store.Hypervisor, &ich.info); err != nil {
		ich.Logger().WithField("function", "createSandbox").WithError(err).Info("No info could be fetched")
	}
	
	ichPath, err := ich.ichPath()
	if err != nil {
		return err
	}
	
	// Add memory to the cloud hypervisor
	memory, err := ich.arch.appendMemory(ich.config.MemorySize, "/dev/shm")
	if err != nil {
		return err
	}

	// Add vcpu to the cloud hypervisor
	vcpu, err := ich.arch.appendProcessors(ich.config.NumVCPUs)
	if err != nil {
		return err
	}
	
	// Add the kernel parameters and kernel path
	kernelPath, err := ich.config.KernelAssetPath()
	if err != nil {
		return err
	}
	kernel := govmmIch.Kernel{
		Path:       kernelPath,
		Params:     ich.kernelParameters(),
	}
 	 
	ichConfig := govmmIch.Config{
		Name:        fmt.Sprintf("sandbox-%s", ich.id),
		UUID:        ich.state.UUID,
		Path:        ichPath,
		PidFile:     filepath.Join(store.RunVMStoragePath(), ich.id, "pid"),
		Memory:		 memory,
		VCPU:		 vcpu,
		Kernel:      kernel,
	}
	
	// Add RNG device to hypervisor
	rngDev := config.RNGDev{
		ID:       rngID,
		Filename: ich.config.EntropySource,
	}
	ichConfig.Devices, err = ich.arch.appendRNGDevice(ichConfig.Devices, rngDev)
	
	// Add the hybrid vsock device to hypervisor
	vsockDev := types.HybridVSock {
		UdsPath: 	ich.socketPath,
		Port: 		1024,
	}
	ichConfig.Devices, err = ich.arch.appendHybridVSock(ichConfig.Devices, vsockDev)
	if err != nil {
		return err
	}
	
	// Add the root disk to the hypervisor
	imagePath, err := ich.config.ImageAssetPath()
	if err != nil {
		return err
	}

	if imagePath != "" {
		ichConfig.Devices, err = ich.arch.appendImage(ichConfig.Devices, imagePath)
		if err != nil {
			return err
		}
	}
	 
	// Add the virtio-fs to the hypervisor
	vfsdSockPath, err := ich.vfsdFSSocketPath(ich.id)
	if err != nil {
		return err
	}	
	if vfsdSockPath != "" {
		ichConfig.Devices, err = ich.arch.appendVirtualFilesystem(ichConfig.Devices, "kataShared", vfsdSockPath)
		if err != nil {
			return err
		}
	}
	
	// Add the serial console to the cloud hypervisor
	if ich.config.Debug {
		ichConfig.Devices, err = ich.arch.appendSerialConsole(ichConfig.Devices, "file=/tmp/ich.log")
	} else {
		ichConfig.Devices, err = ich.arch.appendSerialConsole(ichConfig.Devices, "off")
	}
	if err != nil {
		return err
	}
	
	// Add the virtio console to the cloud hypervisor
	ichConfig.Devices, err = ich.arch.appendVirtioConsole(ichConfig.Devices, "off")
	if err != nil {
		return err
	}
	 
	// Add the http api endpoint to the cloud hypervisor by default
//	apiSocketPath, err := ich.apiSocketPath(ich.id)
//	if err != nil {
//		return err
//	}
	
//	ichConfig.Devices, err = ich.arch.appendApiSocket(ichConfig.Devices, apiSocketPath)
//	if err != nil {
//		return err
//	}

		
	ich.ichConfig = ichConfig
	return nil
}

func (ich *cloudHypervisor) startSandbox(timeout int) error {
	span, _ := ich.trace("startSandbox")
	defer span.Finish()
	
	ich.Logger().WithField("function", "startSandbox").Info("starting Sandbox")

	vmPath := filepath.Join(store.RunVMStoragePath(), ich.id)
	err := os.MkdirAll(vmPath, store.DirMode)
	if err != nil {
		return err
	}
	ich.Logger().WithField("function", "startSandbox").Infof("Starting virtiofsd") 
	if ich.config.SharedFS == config.VirtioFS {
		timeout, err = ich.setupVirtiofsd(timeout)
		if err != nil {
			return err
		}
		if err = ich.storeState(); err != nil {
			return err
		}
	}
	
	ich.Logger().WithField("function", "startSandbox").Infof("virtiofsd starts sharing") 
	
	var strErr string
	var thePid = 0
	strErr, err, thePid = govmmIch.LaunchIch(ich.ichConfig)
	if err != nil {
		return fmt.Errorf("fail to launch cloud-hypervisor: %s, error messages from log: %s", err, strErr)
	}		
	if err := ich.waitVMM(ichTimeout); err != nil {
		ich.Logger().WithField("cloud-hypervisor init failed:", err).Warn()
		return err
	}

	ich.info.PID = thePid
	ich.state.PID = thePid
	ich.state.set(ichReady)
	ich.storeState()

	return nil
}

func (ich *cloudHypervisor) getSandboxConsole(id string) (string, error) {
	ich.Logger().WithField("function", "getSandboxConsole").WithField("ID", id).Info("Get Sandbox Console")
	// TODO
	return "", nil
}

func (ich *cloudHypervisor) disconnect() {
	ich.Logger().WithField("function", "disconnect").Info("Disconnecting Sandbox Console")
}

func (ich *cloudHypervisor) getThreadIDs() (vcpuThreadIDs, error) {

	ich.Logger().WithField("function", "getThreadIDs").Info("get thread ID's")

	var vcpuInfo vcpuThreadIDs

	vcpuInfo.vcpus = make(map[int]int)

	return vcpuInfo, nil
}

func (ich *cloudHypervisor) hotplugAddDevice(devInfo interface{}, devType deviceType) (interface{}, error) {
	ich.Logger().WithField("function", "hotplugAddDevice").Info("Add hotplug device")
	return nil, nil
}

func (ich *cloudHypervisor) hotplugRemoveDevice(devInfo interface{}, devType deviceType) (interface{}, error) {
	ich.Logger().WithField("function", "hotplugRemoveDevice").Info("Remove hotplug device")
	return nil, nil
}

func (ich *cloudHypervisor) hypervisorConfig() HypervisorConfig {
	ich.Logger().WithField("function", "hypervisorConfig").Info("get hypervisor config")
	return ich.config
}

func (ich *cloudHypervisor) resizeMemory(reqMemMB uint32, memoryBlockSizeMB uint32, probe bool) (uint32, memoryDevice, error) {
	ich.Logger().WithFields(log.Fields{
		"function":       "resizeMemory",
		"reqMemMB":       reqMemMB,
		"memBlockSizeMB": memoryBlockSizeMB,
	}).Info("resize the VCPU's ")
	return 0, memoryDevice{}, nil
}

func (ich *cloudHypervisor) resizeVCPUs(reqVCPUs uint32) (currentVCPUs uint32, newVCPUs uint32, err error) {

	ich.Logger().WithFields(log.Fields{
		"function": "resizeVCPUs",
		"curr":     currentVCPUs,
		"new":      newVCPUs,
	}).Info("resize the VCPU's ")
	return 0, 0, nil
}

func (ich *cloudHypervisor) cleanup() error {
	ich.Logger().WithField("function", "cleanup").Info("cleanup")
	return nil
}

func (ich *cloudHypervisor) pid() int {
	return ich.info.PID
}

func (ich *cloudHypervisor) pauseSandbox() error {
	ich.Logger().WithField("function", "pauseSandbox").Info("Pause Sandbox")
	return nil
}

func (ich *cloudHypervisor) saveSandbox() error {
	ich.Logger().WithField("function", "saveSandboxC").Info("Save Sandbox")
	return nil
}

func (ich *cloudHypervisor) resumeSandbox() error {
	ich.Logger().WithField("function", "resumeSandbox").Info("Resume Sandbox")
	return nil
}

// stopSandbox will stop the Sandbox's VM.
func (ich *cloudHypervisor) stopSandbox() (err error) {
	span, _ := ich.trace("stopSandbox")
	defer span.Finish()
	ich.Logger().WithField("function", "stopSandbox").Info("Stop Sandbox")
	return ich.terminate()
}

func (ich *cloudHypervisor) fromGrpc(ctx context.Context, hypervisorConfig *HypervisorConfig, store *store.VCStore, j []byte) error {
	return errors.New("cloudHypervisor is not supported by VM cache")
}

func (ich *cloudHypervisor) toGrpc() ([]byte, error) {
	return nil, errors.New("cloudHypervisor is not supported by VM cache")
}

func (ich *cloudHypervisor) save() (s persistapi.HypervisorState) {
	s.Pid = ich.info.PID
	s.Type = string(IchHypervisor)
	return
}

func (ich *cloudHypervisor) load(s persistapi.HypervisorState) {
	ich.info.PID = s.Pid
}

func (ich *cloudHypervisor) check() error {
	// TODO

	return nil
}

func (ich *cloudHypervisor) getPids() []int {
	

	var pids []int
	pids = append(pids, ich.info.PID)

	return pids
}

//#####################################
//
// Local helper methods
//
//#####################################

func (ich *cloudHypervisor) addDevice(devInfo interface{}, devType deviceType) error {
	span, _ := ich.trace("addDevice")
	defer span.Finish()
	
	var err error
    ich.state.RLock()
	switch v := devInfo.(type) {
	case Endpoint:
		ich.Logger().WithField("function", "addDevice").Info(fmt.Sprintf("Adding Endpoint of type %v", v))
		ich.ichConfig.Devices, err = ich.arch.appendNetwork(ich.ichConfig.Devices, v)
	default:
		ich.Logger().WithField("function", "addDevice").Info("Add device of type ", devType, v)
	}

	
	defer ich.state.RUnlock()

	return err
}

func (ich *cloudHypervisor) ichAddVsock(vs types.VSock) error {
	
	ich.Logger().WithField("function", "ichAddVsock").Info("Add vsock device contextID=", vs.ContextID)
	return nil
}

func (ich *cloudHypervisor) Logger() *log.Entry {
	return virtLog.WithField("subsystem", "cloudHypervisor")
}

func (ich *cloudHypervisor) capabilities() types.Capabilities {
	span, _ := ich.trace("capabilities")
	defer span.Finish()

	ich.Logger().WithField("function", "capabilities").Info("get Capabilities")
	return ich.arch.capabilities()
	
}

func (ich *cloudHypervisor) trace(name string) (opentracing.Span, context.Context) {

	if ich.ctx == nil {
		ich.Logger().WithField("type", "bug").Error("trace called before context set")
		ich.ctx = context.Background()
	}

	span, ctx := opentracing.StartSpanFromContext(ich.ctx, name)

	span.SetTag("subsystem", "cloudHypervisor")
	span.SetTag("type", "ich")

	return span, ctx
}


func (ich *cloudHypervisor) terminate() (err error) {
	span, _ := ich.trace("terminate")
	defer span.Finish()

	defer func() {
		if err != nil {
			ich.Logger().Info("Terminate Cloud Hypervisor failed")
		} else {
			ich.Logger().Info("Cloud Hypervisor stopped")
			ich.info.PID = 0
			ich.state.PID = 0
			ich.state.VirtiofsdPid = 0	
			ich.state.set(ichNotReady)
			ich.storeState()
			ich.Logger().Debug("removing virtiofsd and vm sockets")
			path, err := ich.vfsdFSSocketPath(ich.id)
			if(err == nil) {
				rerr := os.Remove(path)
				if(rerr != nil) {
					ich.Logger().WithField("path", path).Warn("removing virtiofsd socket failed")
				}
			}
			path, err = ich.vsockSocketPath(ich.id)
			if(err == nil) {
				rerr := os.Remove(path)
				if(rerr != nil) {
					ich.Logger().WithField("path", path).Warn("removing vm socket failed")
				}
			}
		}
	}()

	pid := ich.info.PID
	if(pid == 0) {
		ich.Logger().WithField("PID", pid).Info("Skipping kill cloud hypervisor. invalid pid")
		return nil
	}
	ich.Logger().WithField("PID", pid).Info("Stopping Cloud Hypervisor")

	// Check if VM process is running, in case it is not, let's
	// return from here.
	if err = syscall.Kill(pid, syscall.Signal(0)); err != nil {
		return nil
	}

	// Send a SIGTERM to the VM process to try to stop it properly
	if err = syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return err
	}

	// Wait for the VM process to terminate
	tInit := time.Now()
	for {
		if err = syscall.Kill(pid, syscall.Signal(0)); err != nil {
			return nil
		}

		if time.Since(tInit).Seconds() >= fcStopSandboxTimeout {
			ich.Logger().Warnf("VM still running after waiting %ds", fcStopSandboxTimeout)
			break
		}

		// Let's avoid to run a too busy loop
		time.Sleep(time.Duration(50) * time.Millisecond)
	}
	
	// Let's try with a hammer now, a SIGKILL should get rid of the
	// VM process.
	return syscall.Kill(pid, syscall.SIGKILL)
}

func (ich *cloudHypervisor) generateSocket(id string, useVsock bool) (interface{}, error) {
	if !useVsock {
		return nil, fmt.Errorf("Can't generate socket path for cloud-hypervisor: vsocks is disabled")
	}

	udsPath, err := ich.vsockSocketPath(id)
	if err != nil {
			ich.Logger().Info("Can't generate socket path for cloud-hypervisor")
			return types.HybridVSock{}, err
	}
	ich.Logger().WithField("function", "generateSocket").Infof("Using hybrid vsock %s:%d", udsPath, vSockPort)
	ich.socketPath = udsPath;
	return types.HybridVSock {
		UdsPath: udsPath,
		Port:    uint32(vSockPort),
	}, nil
}

func (ich *cloudHypervisor) setupVirtiofsd(timeout int) (remain int, err error) {
	
	sockPath, perr := ich.vfsdFSSocketPath(ich.id)
	if perr != nil {
		return 0, perr
	}
	
	theArgs, err := ich.virtiofsdArgs(sockPath)
	if(err != nil) {
		return 0, err
	}
	
	ich.Logger().WithField("Path", ich.config.VirtioFSDaemon).Info()
	ich.Logger().WithField("Args", strings.Join(theArgs, " ")).Info()

	cmd := exec.Command(ich.config.VirtioFSDaemon, theArgs...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, err
	}

	if err = cmd.Start(); err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			ich.state.VirtiofsdPid = 0			
			cmd.Process.Kill()
		} else {
			ich.state.VirtiofsdPid = cmd.Process.Pid
			
		}
		ich.storeState()
	}()

	// Wait for socket to become available
	sockReady := make(chan error, 1)
	timeStart := time.Now()
	go func() {
		scanner := bufio.NewScanner(stderr)
		var sent bool
		for scanner.Scan() {
			if ich.config.Debug {
				ich.Logger().WithField("source", "virtiofsd").Debug(scanner.Text())
			}
			if !sent && strings.Contains(scanner.Text(), "Waiting for vhost-user socket connection...") {
				sockReady <- nil
				sent = true
			}
		}
		if !sent {
			if err := scanner.Err(); err != nil {
				sockReady <- err
			} else {
				sockReady <- fmt.Errorf("virtiofsd did not announce socket connection")
			}
		}
		ich.Logger().Info("virtiofsd quits")
		// Wait to release resources of virtiofsd process
		cmd.Process.Wait()		
		
	}()

	return ich.waitVirtiofsd(timeStart, timeout, sockReady,
		fmt.Sprintf("virtiofsd (pid=%d) socket %s", cmd.Process.Pid, sockPath))
}

func (ich *cloudHypervisor) waitVirtiofsd(start time.Time, timeout int, ready chan error, errMsg string) (int, error) {
	var err error

	timeoutDuration := time.Duration(timeout) * time.Second
	select {
	case err = <-ready:
	case <-time.After(timeoutDuration):
		err = fmt.Errorf("timed out waiting for %s", errMsg)
	}
	if err != nil {
		return 0, err
	}

	// Now reduce timeout by the elapsed time
	elapsed := time.Since(start)
	if elapsed < timeoutDuration {
		timeout = timeout - int(elapsed.Seconds())
	} else {
		timeout = 0
	}
	return timeout, nil
}


func (ich *cloudHypervisor) virtiofsdArgs(sockPath string) ([]string, error) {

	sourcePath := filepath.Join(kataHostSharedDir(), ich.id)
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		os.MkdirAll(sourcePath, os.ModePerm)
	}

	args := []string{
		"-f",
		"-o", "vhost_user_socket=" + sockPath,
		"-o", "source=" + sourcePath,
		"-o", "cache=" + ich.config.VirtioFSCache}


	if len(ich.config.VirtioFSExtraArgs) != 0 {
		args = append(args, ich.config.VirtioFSExtraArgs...)
	}
	return args, nil
}

func (ich *cloudHypervisor) vfsdFSSocketPath(id string) (string, error) {
	return utils.BuildSocketPath(store.RunVMStoragePath(), id, vfsdSocket)
}
func (ich *cloudHypervisor) vsockSocketPath(id string) (string, error) {
	return utils.BuildSocketPath(store.RunVMStoragePath(), id, ichSocket)
}
func (ich *cloudHypervisor) apiSocketPath(id string) (string, error) {
	return utils.BuildSocketPath(store.RunVMStoragePath(), id, apiSocket)
}

func (ich *cloudHypervisor) storeState() error {
	if ich.store != nil {
		if err := ich.store.Store(store.Hypervisor, ich.state); err != nil {
			return err
		}
	}
	return nil
}

func (ich *cloudHypervisor) waitVMM(timeout int) error {
	
	var err error
	timeoutDuration := time.Duration(timeout) * time.Second
	
	sockReady := make(chan error, 1)
	go func() {
		udsPath, err := ich.vsockSocketPath(ich.id)
		if(err != nil) {
			sockReady <- err
		}
		
		for {
			addr, err := net.ResolveUnixAddr("unix", udsPath)
			if(err != nil) {
				sockReady <- err
			}
			conn, err := net.DialUnix("unix", nil, addr)
		
			if(err != nil) {
				time.Sleep(50 * time.Millisecond)
			} else {
				conn.Close()
				sockReady <- nil
				
				break;
			}
		}
	}()
	
	select {
	case err = <-sockReady:
	case <-time.After(timeoutDuration):
		err = fmt.Errorf("timed out waiting for cloud-hypervisor vsock")
	}
	// delay between vsock is available but hypervisor is bstill ooting and starting the kata-agent
	// this should be re-visited. TODO
	time.Sleep(1000 * time.Millisecond) 
	return err
}

func (ich *cloudHypervisor) ichPath() (string, error) {
	p, err := ich.config.HypervisorAssetPath()
	if err != nil {
		return "", err
	}

	if p == "" {
		p, err = ich.arch.ichPath()
		if err != nil {
			return "", err
		}
	}

	if _, err = os.Stat(p); os.IsNotExist(err) {
		return "", fmt.Errorf("Cloud-Hypervisor path (%s) does not exist", p)
	}

	return p, nil
}

func (ich *cloudHypervisor) kernelParameters() string {

	// prepare the kernel parameters
	var cmdline strings.Builder
	
	// First take the default parameters defined by this driver
	for _, p := range ichKernelParams {
		cmdline.WriteString(p.Key)
		if len(p.Value) > 0 {
			
			cmdline.WriteString("=")
			cmdline.WriteString(p.Value)
		}
		cmdline.WriteString(" ")				
	}
	
	// Followed by extra debug parameters if debug enabled in configuration file
	if(ich.config.Debug == true) {
		for _, p := range ichDebugKernelParams {
		cmdline.WriteString(p.Key)
		if len(p.Value) > 0 {
			
			cmdline.WriteString("=")
			cmdline.WriteString(p.Value)
		}
		cmdline.WriteString(" ")		}
	}
	
	// Followed by extra debug parameters defined in the configuration file
	for _, p := range ich.config.KernelParams {
		
		cmdline.WriteString(p.Key)
		if len(p.Value) > 0 {
			
			cmdline.WriteString("=")
			cmdline.WriteString(p.Value)
		}
		cmdline.WriteString(" ")

	}
	
	return strings.TrimSpace(cmdline.String())
}

