package virtcontainers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kata-containers/runtime/virtcontainers/device/config"
	persistapi "github.com/kata-containers/runtime/virtcontainers/persist/api"
	chclient "github.com/kata-containers/runtime/virtcontainers/pkg/cloud-hypervisor/client"
	"github.com/kata-containers/runtime/virtcontainers/store"
	"github.com/kata-containers/runtime/virtcontainers/types"
	"github.com/kata-containers/runtime/virtcontainers/utils"
	"github.com/sirupsen/logrus"
)

const (
	apiSocket             = "api.sock"
	clhStopSandboxTimeout = 15
)

type cloudHypervisorState struct {
	apiSocket string
	pid       int
}

type cloudHypervisor struct {
	id        string
	store     *store.VCStore
	config    HypervisorConfig
	state     cloudHypervisorState
	ApiClient *chclient.DefaultApiService
	vmconfig  chclient.VmConfig
}

// INIT hypervisor interface implementation functions
func (c *cloudHypervisor) createSandbox(ctx context.Context, id string, networkNS NetworkNamespace, hypervisorConfig *HypervisorConfig, vcstore *store.VCStore) error {
	c.Logger().Debug("Creating Sandbox using cloud-hypervisor")

	err := hypervisorConfig.valid()
	if err != nil {
		return err
	}

	c.id = id
	c.store = vcstore
	c.config = *hypervisorConfig

	vmPath := filepath.Join(store.RunVMStoragePath(), c.id)
	if err := os.MkdirAll(vmPath, store.DirMode); err != nil {
		return err
	}
	apiSocket, err := utils.BuildSocketPath(store.RunVMStoragePath(), c.id, apiSocket)
	if err != nil {
		return err
	}
	c.state.apiSocket = apiSocket

	return nil
}

func (c *cloudHypervisor) startSandbox(timeout int) error {
	if c.config.SharedFS != config.VirtioFS {
		return fmt.Errorf("not configured to use virtiofs")
	}

	_, err := startVirtiofsd(c.id, c.config, c.vmconfig.Fs[0].Sock)
	if err != nil {
		return err
	}

	if err := c.Start(timeout); err != nil {
		return err
	}

	return nil
}
func (c *cloudHypervisor) stopSandbox() error {
	return nil
}

func (c *cloudHypervisor) pauseSandbox() error {
	return nil
}

func (c *cloudHypervisor) saveSandbox() error {
	return nil
}

func (c *cloudHypervisor) resumeSandbox() error {
	return nil
}

func (c *cloudHypervisor) addDevice(devInfo interface{}, devType deviceType) error {

	devLogger := c.Logger().WithFields(logrus.Fields{
		"action": "addDevice",
	})

	switch v := devInfo.(type) {
	case types.Volume:

		if c.config.SharedFS != config.VirtioFS {
			return fmt.Errorf("shared fs method not supported %s", c.config.SharedFS)
		}

		fsSocket, err := utils.BuildSocketPath(store.RunVMStoragePath(), c.id, "vfs.sock")
		if err != nil {
			return err
		}
		c.vmconfig.Fs = []chclient.FsConfig{
			{
				Tag:       v.MountTag,
				CacheSize: int64(c.config.VirtioFSCacheSize << 20),
				Sock:      fsSocket,
				//TODO
				NumQueues: 1,
				//TODO
				QueueSize: 512,
			},
		}
		devLogger.Debug("Adding Volume to hypervisor ", v.HostPath, ":", v.MountTag)
	case types.HybridVSock:
		devLogger.Debugf("Adding vsock to hypervisor %s", v.UdsPath)
		//TODO: fix API to use int64
		c.vmconfig.Vsock = []chclient.VsockConfig{{Cid: int32(defaultGuestVSockCID), Sock: v.UdsPath}}
	case Endpoint:
		n := chclient.NetConfig{}
		n.Mac = v.HardwareAddr()
		n.Tap = v.NetworkPair().TapInterface.TAPIface.Name

		//TODO server does not allow empty IP fail serde to get it
		n.Ip = "0.0.0.0"
		n.Mask = "0.0.0.0"
		c.vmconfig.Net = append(c.vmconfig.Net, n)

		return nil
	default:
		devLogger.Debugf("Adding %s to hypervisor", v)
		return fmt.Errorf("Not implemented support for %s", v)
	}
	return nil
}

func (c *cloudHypervisor) hotplugAddDevice(devInfo interface{}, devType deviceType) (interface{}, error) {
	return nil, nil
}

func (c *cloudHypervisor) hotplugRemoveDevice(devInfo interface{}, devType deviceType) (interface{}, error) {
	return nil, nil
}

func (c *cloudHypervisor) resizeMemory(memMB uint32, memoryBlockSizeMB uint32, probe bool) (uint32, memoryDevice, error) {
	return 0, memoryDevice{}, nil
}

func (c *cloudHypervisor) resizeVCPUs(vcpus uint32) (uint32, uint32, error) {
	return 0, 0, nil
}

func (c *cloudHypervisor) getSandboxConsole(sandboxID string) (string, error) {
	return "", nil
}

func (c *cloudHypervisor) disconnect() {
	return
}

func (c *cloudHypervisor) capabilities() types.Capabilities {
	return types.Capabilities{}
}

func (c *cloudHypervisor) hypervisorConfig() HypervisorConfig {
	return HypervisorConfig{}
}

func (c *cloudHypervisor) getThreadIDs() (vcpuThreadIDs, error) {
	return vcpuThreadIDs{}, nil
}

func (c *cloudHypervisor) cleanup() error {
	return nil
}

func (c *cloudHypervisor) getPids() []int {
	return []int{}
}

func (c *cloudHypervisor) fromGrpc(ctx context.Context, hypervisorConfig *HypervisorConfig, store *store.VCStore, j []byte) error {
	return nil
}

func (c *cloudHypervisor) toGrpc() ([]byte, error) {
	return []byte{}, nil
}

func (c *cloudHypervisor) check() error {
	return nil
}

func (c *cloudHypervisor) save() persistapi.HypervisorState {
	return persistapi.HypervisorState{}
}

func (c *cloudHypervisor) load(persistapi.HypervisorState) {
	return
}

func (c *cloudHypervisor) generateSocket(id string, useVsock bool) (interface{}, error) {
	return generateVMSocket(id, &vsockInfo{hybrid: true})
}

// END hypervisor interface implementation functions

func (c *cloudHypervisor) storeState() error {
	//TODO: should be mixed with save method?
	if c.store != nil {
		if err := c.store.Store(store.Hypervisor, c.state); err != nil {
			return err
		}
	}
	return nil
}

func (c *cloudHypervisor) Logger() *logrus.Entry {
	return virtLog.WithField("subsystem", "cloud-hypervisor")
}

func (c *cloudHypervisor) isRunning() bool {
	// Todo if we launched and have not wait for it this will return 0 but the process
	// is zombie, need extra check to no is running ?
	if err := syscall.Kill(c.state.pid, syscall.Signal(0)); err != nil {
		return false
	}
	return true
}

func (c *cloudHypervisor) Start(timeout int) error {
	// start api server
	var args []string
	var cmd *exec.Cmd
	args = []string{"--api-socket", c.state.apiSocket}
	cmd = exec.Command(c.config.HypervisorPath, args...)

	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput

	file, err := os.Create("/tmp/ch-stdout.log")
	if err != nil {
		return err
	}

	defer file.Close()
	cmd.Stdout = file
	cmd.Stderr = file
	c.Logger().WithField("hypervisor cmd", cmd.Path).Debug()
	c.Logger().WithField("hypervisor args", cmd.Args).Debug()

	if err := cmd.Start(); err != nil {
		c.Logger().WithField("Error starting hypervisor", err).Error()
		return err
	}
	c.state.pid = cmd.Process.Pid
	// end start server

	if err := c.waitAPIServer(timeout); err != nil {
		return err
	}

	if err := c.bootVM(timeout); err != nil {
		return err
	}
	//cmd.Wait()

	return nil
}

func (c *cloudHypervisor) isClhRunning(timeout int) (bool, error) {
	// todo: add tracing/logging
	if timeout < 0 {
		return false, fmt.Errorf("Invalid timeout %ds", timeout)
	}

	pid := c.state.pid

	// Check if clh process is running, in case it is not, let's
	// return from here.
	if err := syscall.Kill(pid, syscall.Signal(0)); err != nil {
		return false, nil
	}

	ctx := context.Background()
	timeStart := time.Now()
	cl := c.client()
	for {
		_, _, err := cl.VmmPingGet(ctx)
		if err == nil {
			return true, nil
		}

		if int(time.Since(timeStart).Seconds()) > timeout {
			return false, fmt.Errorf("Failed to connect to API (timeout %ds): %s", timeout, openApiClientError(err))
		}

		time.Sleep(time.Duration(10) * time.Millisecond)
	}

}

func (c *cloudHypervisor) waitAPIServer(timeout int) error {
	// TODO: Add tracing
	clh_running, err := c.isClhRunning(timeout)

	if err != nil {
		return err
	}

	if !clh_running {
		return fmt.Errorf("CLH is not running")
	}

	return nil
}

func openApiClientError(err error) error {

	if err == nil {
		return nil
	}

	reason := ""
	if apierr, ok := err.(chclient.GenericOpenAPIError); ok {
		reason = string(apierr.Body())
	}

	return fmt.Errorf("error: %v reason: %s", err, reason)
}

func (c *cloudHypervisor) bootVM(timeout int) error {
	// TODO: Add tracing

	if timeout < 0 {
		return fmt.Errorf("Invalid timeout %ds", timeout)
	}

	ctx := context.Background()

	kernelPath, err := c.config.KernelAssetPath()
	if err != nil {
		return err
	}

	imagePath, err := c.config.ImageAssetPath()
	if err != nil {
		return err
	}

	chKernelCmdline := append(commonVirtioblkKernelRootParams, []Param{
		// TODO refactor with fc
		{"agent.log_vport", fmt.Sprintf("%d", vSockLogsPort)},
		{"console", "hvc0"},
		{"ch_params", "end"},
	}...)
	kernelCmdline := append(chKernelCmdline, c.config.KernelParams...)
	// Get Kernel params
	strParams := SerializeParams(kernelCmdline, "=")
	kernel_cmdline := strings.Join(strParams, " ")

	// Kernel config
	c.vmconfig.Kernel.Path = kernelPath
	c.vmconfig.Cmdline.Args = kernel_cmdline

	// Disk config
	c.vmconfig.Disks = []chclient.DiskConfig{{Path: imagePath}}

	// Initial VM Reesources
	c.vmconfig.Cpus.CpuCount = int32(c.config.NumVCPUs)
	// TODO
	/// vmconfig.Memory.Size = c.config.MemorySize
	// api wrapper convert to u32, need to fix with
	// type: integer
	//format: int64
	c.vmconfig.Memory.Size = 536870912
	c.vmconfig.Memory.File = "/dev/shm"

	c.vmconfig.Console = chclient.ConsoleConfig{Mode: "File", File: "/tmp/chapi.log"}
	c.vmconfig.Serial = chclient.ConsoleConfig{Mode: "Off"}

	// No default value and goes emtpy
	c.vmconfig.Rng.Src = "/dev/urandom"

	c.Logger().Debugf("VMconfig %#v", c.vmconfig)

	cl := c.client()
	bodyBuf, err := json.Marshal(c.vmconfig)
	if err != nil {
		return err
	}
	c.Logger().Debugf("%s", string(bodyBuf))
	_, err = cl.CreateVM(ctx, c.vmconfig)

	if err != nil {
		return openApiClientError(err)
	}

	info, _, err := cl.VmInfoGet(ctx)

	if err != nil {
		return openApiClientError(err)
	}

	c.Logger().Debugf("VM state after create: %#v", info)

	if info.State != "Created" {
		return fmt.Errorf("VM state is not created after create")
	}

	c.Logger().Debug("Booting VM")
	_, err = cl.BootVM(ctx)

	if err != nil {
		return openApiClientError(err)
	}

	info, _, err = cl.VmInfoGet(ctx)

	if err != nil {
		return openApiClientError(err)
	}

	c.Logger().Debugf("VM state after boot: %#v", info)

	if info.State != "Running" {
		return fmt.Errorf("VM state is not created after create")
	}

	return nil
}

func (c *cloudHypervisor) client() *chclient.DefaultApiService {
	if c.ApiClient == nil {
		c.ApiClient = c.newAPIClient()
	}

	return c.ApiClient
}

func (c *cloudHypervisor) newAPIClient() *chclient.DefaultApiService {

	cfg := chclient.NewConfiguration()

	socketTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, path string) (net.Conn, error) {
			addr, err := net.ResolveUnixAddr("unix", c.state.apiSocket)
			if err != nil {
				return nil, err

			}

			return net.DialUnix("unix", nil, addr)
		},
	}

	cfg.HTTPClient = http.DefaultClient
	cfg.HTTPClient.Transport = socketTransport

	return chclient.NewAPIClient(cfg).DefaultApi
}
