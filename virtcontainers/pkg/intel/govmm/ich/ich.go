package ich

import (

	"context"
	"os/exec"
	"fmt"
	"strconv"
	"strings"
	"io/ioutil"
	"github.com/sirupsen/logrus"
)

type Device interface {
	Valid() bool
	IchParams(config *Config) []string
}

type Config struct {
	
	Name string
	UUID string
	Path string
	PidFile string
	Devices []Device
	Ctx context.Context
	ichParams []string
	Memory Memory 
	VCPU VCPU
	Kernel Kernel

}



const (
	// TAP is a TAP networking device type.
	TAP NetDeviceType = "tap"

	// MACVTAP is a macvtap networking device type.
	MACVTAP NetDeviceType = "macvtap"

	// IPVTAP is a ipvtap virtual networking device type.
	IPVTAP NetDeviceType = "ipvtap"

	// VETHTAP is a veth-tap virtual networking device type.
	VETHTAP NetDeviceType = "vethtap"

	// VFIO is a direct assigned PCI device or PCI VF
	VFIO NetDeviceType = "VFIO"

	// VHOSTUSER is a vhost-user port (socket)
	VHOSTUSER NetDeviceType = "vhostuser"
)

type Memory struct {
	// Size is the amount of memory made available to the guest.
	// It should be suffixed with M or G for sizes in megabytes or
	// gigabytes respectively.
	Size string
	// Path is the file path of the memory device. It points to a local
	// file path used by FileBackedMem.
	Path string
}

type VCPU struct {
	
	Size uint32
	
}

// Kernel is the guest kernel configuration structure.
type Kernel struct {
	// Path is the guest kernel path on the host filesystem.
	Path string

	// Params is the kernel parameters string.
	Params string
}

// Object is a ich object representation.
type Object struct {

	// ID is the user defined object ID.
	ID string

}

// Valid returns true if the Object structure is valid and complete.
func (object Object) Valid() bool {

	return true
}

// QemuParams returns the qemu parameters built out of this Object device.
func (object Object) IchParams(config *Config) []string {

	var ichParams []string

	// TODO
	
	return ichParams
}


/************************************************************************************
 *
 * NetDeviceType is a ich networking device type.
 *
*************************************************************************************/ 
type NetDeviceType string

type NetDevice struct {
	// Type is the netdev type (e.g. tap).
	Type NetDeviceType

	// ID is the netdevice identifier.
	ID string

	// IfName is the interface name,
	IFName string

	// VHost enables virtio device emulation from the host kernel instead of from qemu.
	VHost bool

	// MACAddress is the networking device interface MAC address.
	MACAddress string


}

// IchParams returns the ich parameters built out of this network device.
func (netdev NetDevice) IchParams(config *Config) []string {
	
	var ichParams []string

	// TODO more then 1 netdev needs improvements.

	ichParams = append(ichParams, "--net", fmt.Sprintf("tap=%s,mac=%s", netdev.IFName, netdev.MACAddress))

	return ichParams
}

// Valid returns true if the NetDevice structure is valid and complete.
func (netdev NetDevice) Valid() bool {
	if netdev.ID == "" || netdev.IFName == "" {
		return false
	}

	switch netdev.Type {
	case TAP:
		return true
	default:
		return false
	}
}

/************************************************************************************
 *
 * DiskDevice represents the path to the (root) disk image
 *
*************************************************************************************/  
type DiskDevice struct {

	Path string

}

// IchParams returns the ich parameters built out of this network device.
func (diskdev DiskDevice) IchParams(config *Config) []string {
	
	var ichParams []string

	ichParams = append(ichParams, "--disk", fmt.Sprintf("path=%s", diskdev.Path))

	return ichParams
}

// Valid returns true if the NetDevice structure is valid and complete.
func (diskdev DiskDevice) Valid() bool {
	if diskdev.Path == "" {
		return false
	}	
	return true
}

/************************************************************************************
 *
 * VirtioFSDevice represents a virtio shared filesystem
 *
*************************************************************************************/  
type VirtioFSDevice struct {

	Path string
	Tag string
	NumQueues uint32
	QueueSize uint32
	Dax	bool
	CacheSize uint64

}

// IchParams returns the ich parameters built out of this network device.
func (vfsdev VirtioFSDevice) IchParams(config *Config) []string {
	
	var ichParams []string

	
	daxParam := "off"
	cacheSize := "0Gib"
	if(vfsdev.Dax) {
		daxParam = "on"
		cacheSize = "8Gib"
		ichParams = append(ichParams, "--fs", fmt.Sprintf("tag=%s,sock=%s,num_queues=%d,queue_size=%d,dax=%s,cache_size=%s", 
				vfsdev.Tag,
				vfsdev.Path,
				vfsdev.NumQueues,
				vfsdev.QueueSize,
				daxParam,
				cacheSize,
		))
	} else {
		ichParams = append(ichParams, "--fs", fmt.Sprintf("tag=%s,sock=%s,num_queues=%d,queue_size=%d", 
				vfsdev.Tag,
				vfsdev.Path,
				vfsdev.NumQueues,
				vfsdev.QueueSize,
		))	
	}
	
	return ichParams
}

// Valid returns true if the VirtioFSDevice structure is valid and complete.
func (vfsdev VirtioFSDevice) Valid() bool {
	if vfsdev.Path == "" {
		return false
	}
	if vfsdev.Tag == "" {
		return false
	}	
	return true
}

/************************************************************************************
 *
 * SerialConsoleDevice represents the serial console
 *
*************************************************************************************/  
type SerialConsoleDevice struct {

	ConsoleType string

}

// IchParams returns the ich parameters built out of this network device.
func (scondev SerialConsoleDevice) IchParams(config *Config) []string {
	
	var ichParams []string

	ichParams = append(ichParams, "--serial", scondev.ConsoleType)

	return ichParams
}

// Valid returns true if the NetDevice structure is valid and complete.
func (scondev SerialConsoleDevice) Valid() bool {
	if scondev.ConsoleType == "" {
		return false
	}	// TODO refine
	return true
}

/************************************************************************************
 *
 *VirtioConsoleDevice represents the virtio console
 *
*************************************************************************************/  
type VirtioConsoleDevice struct {

	ConsoleType string

}

// IchParams returns the ich parameters built out of this network device.
func (vcondev VirtioConsoleDevice) IchParams(config *Config) []string {
	
	var ichParams []string

	ichParams = append(ichParams, "--console", vcondev.ConsoleType)

	return ichParams
}

// Valid returns true if the NetDevice structure is valid and complete.
func (vcondev VirtioConsoleDevice) Valid() bool {
	if vcondev.ConsoleType == "" {
		return false
	}	// TODO refine
	return true
}

/************************************************************************************
 *
 *ApiEndpointDevice represents the vmm http api endpoint
 *
*************************************************************************************/  
type ApiEndpointDevice struct {

	ApiSocket string

}

// IchParams returns the ich parameters built out of this network device.
func (apidev ApiEndpointDevice) IchParams(config *Config) []string {
	
	var ichParams []string
	
	ichParams = append(ichParams, "--api-socket", apidev.ApiSocket)
	
	return ichParams
}

// Valid returns true if the NetDevice structure is valid and complete.
func (apidev ApiEndpointDevice) Valid() bool {
	
	return true
}

/************************************************************************************
 *
 * HybridVSOCKDevice represents a AF_VSOCK <-> AF_UNIX socket combination.
 *
*************************************************************************************/  
type HybridVSOCKDevice struct {

	Path string
	ContextID uint64
	Port uint32

}

// IchParams returns the ich parameters built out of this network device.
func (sockdev HybridVSOCKDevice) IchParams(config *Config) []string {
	
	var ichParams []string

	strCid := strconv.FormatUint(sockdev.ContextID, 10)
	ichParams = append(ichParams, "--vsock", fmt.Sprintf("cid=%s,sock=%s", strCid, sockdev.Path))

	return ichParams
}

// Valid returns true if the NetDevice structure is valid and complete.
func (sockdev HybridVSOCKDevice) Valid() bool {
	if sockdev.Path == "" {
		return false
	}	
	return true
}


/************************************************************************************
 *
 * RngDevice represents a random number generator device.
 *
*************************************************************************************/  

type RngDevice struct {

	// Filename is entropy source on the host
	Filename string
}

// IchParams returns the ich parameters built out of this network device.
func (rngdev RngDevice) IchParams(config *Config) []string {
	
	var ichParams []string

	ichParams = append(ichParams, "--rng")
	ichParams = append(ichParams,  rngdev.Filename)

	return ichParams
}

func (rngdev RngDevice) Valid() bool {
	if rngdev.Filename == "" {
		return false
	}

	return true
}

/************************************************************************************
 *
 * functions aggregating all device params and launching the hypervisor
 *
*************************************************************************************/  

func (config *Config) appendDevices() {
	for _, d := range config.Devices {
		if !d.Valid() {
			continue
		}
 
		config.ichParams = append(config.ichParams, d.IchParams(config)...)
	}
}

func (config *Config) appendMemory() {
	
	if(config.Memory.Path == "") { 
		config.ichParams = append(config.ichParams, "--memory", fmt.Sprintf("size=%s", config.Memory.Size))
	} else {
		config.ichParams = append(config.ichParams, "--memory", fmt.Sprintf("size=%s,file=%s", config.Memory.Size, config.Memory.Path))
	}
}

func (config *Config) appendProcessors() {
	
	config.ichParams = append(config.ichParams, "--cpus", fmt.Sprintf("%d", config.VCPU.Size))
	
}

func (config *Config) appendKernel() {
	
	//config.ichParams = append(config.ichParams, "--cmdline", fmt.Sprintf("\"%s\"", config.Kernel.Params))
	config.ichParams = append(config.ichParams, "--kernel", config.Kernel.Path)
	config.ichParams = append(config.ichParams, "--cmdline", config.Kernel.Params);
}

func LaunchIch(config Config) (string, error, int) {
	 	
	config.appendDevices()
	config.appendMemory()
	config.appendProcessors()
	config.appendKernel()
	
	ctx := config.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
 
	fmt.Printf("Path %s\n", config.Path);
	fmt.Printf("Args %s\n", strings.Join(config.ichParams, " "));
	
	return LaunchCustomIch(ctx, config.Path, config.ichParams)
}

func LaunchCustomIch(ctx context.Context, path string, params []string) (string, error, int) {
	
	errStr := ""
	
	logrus.WithField("source", "ich").WithField("subsystem", "cloudHypervisor").WithField("Path", path).Info()
	logrus.WithField("source", "ich").WithField("subsystem", "cloudHypervisor").WithField("Args", strings.Join(params, " ")).Info();
	
	cmd := exec.Command(path, params...)
	cmd.Stderr = ioutil.Discard
	

	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting cloudHypervisor", err)
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return errStr,err, 0
	}

	return errStr, nil, cmd.Process.Pid	
}
