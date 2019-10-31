package virtcontainers

import (
	"bytes"
	"context"
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
	apiSocket = "api.sock"
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
	c.Logger().Debug("Creating Sandbox for for cloud-hypervisor")

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
	if err := c.Start(); err != nil {
		return err
	}

	if err := c.waitAPIServer(timeout); err != nil {
		return err
	}

	if err := c.bootVM(timeout); err != nil {
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

	switch v := devInfo.(type) {
	case types.Volume:
		if c.config.SharedFS == config.VirtioFS {
			return fmt.Errorf("VirtioFS not implemented")
		} else {
			return fmt.Errorf("shared fs method not supported")
		}
	case types.Socket:

		return fmt.Errorf("Not implemented Socket")
	case types.VSock:
		return fmt.Errorf("Not implemented VSocket")
	case types.HybridVSock:
		//TODO: fix API to use int64
		c.vmconfig.Vsock = []chclient.VsockConfig{{Cid: int32(defaultGuestVSockCID), Sock: v.UdsPath}}
	case Endpoint:
		return fmt.Errorf("Not implemented Endpoint")
	case config.BlockDrive:
		return fmt.Errorf("Not implemented BlockDrive")
	case config.VhostUserDeviceAttrs:
		return fmt.Errorf("Not implemented VhostUserDeviceAttrs")
	case config.VFIODev:
		return fmt.Errorf("Not implemented VFIODev")
	default:
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

func (c *cloudHypervisor) Start() error {
	var args []string
	var cmd *exec.Cmd
	args = []string{"--api-socket", c.state.apiSocket}
	cmd = exec.Command(c.config.HypervisorPath, args...)

	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput

	c.Logger().WithField("hypervisor cmd", cmd.Path).Debug()
	c.Logger().WithField("hypervisor args", cmd.Args).Debug()

	if err := cmd.Start(); err != nil {
		c.Logger().Errorf("%s", string(cmdOutput.Bytes()))
		c.Logger().WithField("Error starting hypervisor", err).Error()
		return err
	}
	c.state.pid = cmd.Process.Pid

	return nil
}

func (c *cloudHypervisor) waitAPIServer(timeout int) error {
	// TODO: Add tracing

	ctx := context.Background()
	if timeout < 0 {
		return fmt.Errorf("Invalid timeout %ds", timeout)
	}

	timeStart := time.Now()
	cl := c.client()
	for {

		info, res, err := cl.VmmInfoGet(ctx)
		if err == nil {
			c.Logger().Debug("TODO Vmm version ", info.Version)
			fmt.Println("check reponse", info, res)
			return nil
		}

		if int(time.Since(timeStart).Seconds()) > timeout {
			return fmt.Errorf("Failed to connect to API (timeout %ds): %s", timeout, openApiClientError(err))
		}

		time.Sleep(time.Duration(10) * time.Millisecond)
	}
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

	// Get Kernel params
	strParams := SerializeParams(kernelParams, "=")
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

	c.vmconfig.Serial = chclient.ConsoleConfig{Mode: "Tty", File: ""}
	c.vmconfig.Console = chclient.ConsoleConfig{Mode: "Off", File: ""}

	// No default value and goes emtpy
	c.vmconfig.Rng.Src = "/dev/urandom"

	c.Logger().Debugf("VMconfig %#v", c.vmconfig)

	cl := c.client()
	_, err = cl.CreateVM(ctx, c.vmconfig)

	if err != nil {
		return err
	}

	info, _, err := cl.VmInfoGet(ctx)

	if err != nil {
		return err
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
