package virtcontainers

import (
	"context"

	persistapi "github.com/kata-containers/runtime/virtcontainers/persist/api"
	"github.com/kata-containers/runtime/virtcontainers/store"
	"github.com/kata-containers/runtime/virtcontainers/types"
	"github.com/kata-containers/runtime/virtcontainers/utils"
	"github.com/sirupsen/logrus"
)

const (
	apiSocket = "api.sock"
)

// QemuState keeps Qemu's state
type cloudHypervisorState struct {
	apiSocket string
}

type cloudHypervisor struct {
	id     string
	store  *store.VCStore
	config HypervisorConfig
	state  cloudHypervisorState
}

// INIT hypervisor interface implementation functions
func (c *cloudHypervisor) createSandbox(ctx context.Context, id string, networkNS NetworkNamespace, hypervisorConfig *HypervisorConfig, store *store.VCStore) error {
	c.Logger().Debug("Creating Sandbox for dor cloud-hypervisor")

	err := hypervisorConfig.valid()
	if err != nil {
		return err
	}

	c.id = id
	c.store = store
	c.config = *hypervisorConfig
	c.state.apiSocket, err = c.generateAPISocket()
	if err != nil {
		return err
	}

	return nil
}

func (c *cloudHypervisor) startSandbox(timeout int) error {
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

func (c *cloudHypervisor) generateAPISocket() (string, error) {
	return utils.BuildSocketPath(store.RunVMStoragePath(), c.id, apiSocket)
}
func (c *cloudHypervisor) storeState() error {
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
