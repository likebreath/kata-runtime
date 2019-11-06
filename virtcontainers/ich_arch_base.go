package virtcontainers


import (
	
	"fmt"
	"strings"

	"github.com/kata-containers/runtime/virtcontainers/types"
	"github.com/kata-containers/runtime/virtcontainers/device/config"
	
	govmmIch "github.com/kata-containers/runtime/virtcontainers/pkg/intel/govmm/ich"

)

const (
	defaultIchPath            = "/usr/local/bin/cloud-hypervisor"
	defaultIchMachineType     = "x86_64"
)

type ichArch interface {
	
	// ichPath returns the path to the Ich binary
	ichPath() (string, error)

	// kernelParameters returns the kernel parameters
	kernelParameters(debug bool) []Param

	// appendImage appends an image to devices
	appendImage(devices []govmmIch.Device, path string) ([]govmmIch.Device, error)

	// appendNetwork appends a endpoint device to devices
	appendNetwork(devices []govmmIch.Device, endpoint Endpoint) ([]govmmIch.Device, error)

	// appendHybridVSock appends a hybrid vsock PCI to devices
	appendHybridVSock(devices []govmmIch.Device, vsock types.HybridVSock) ([]govmmIch.Device, error)
	
	appendRNGDevice(devices []govmmIch.Device, rngDev config.RNGDev) ([]govmmIch.Device, error)
	
	appendSerialConsole(devices []govmmIch.Device, consoletype string) ([]govmmIch.Device, error)
	
	appendVirtioConsole(devices []govmmIch.Device, consoletype string) ([]govmmIch.Device, error)
	
	appendApiSocket(devices []govmmIch.Device, apiSocket string) ([]govmmIch.Device, error)
	
	appendVirtualFilesystem(devices []govmmIch.Device, tag string, path string) ([]govmmIch.Device, error)
	
	appendMemory(memorySize uint64, path string) (govmmIch.Memory, error)
	
	appendProcessors(vcpu uint32) (govmmIch.VCPU, error)

	//capabilities returns the capabilities supported by ICH
	capabilities() types.Capabilities
	
}

type ichArchBase struct {
	machineType           string
	networkIndex          int
	nestedRun             bool
	vhost                 bool	
	kernelParams          []Param
	memory				  govmmIch.Memory
	vcpu				  govmmIch.VCPU
}


func newIchArch(config HypervisorConfig) ichArchBase {
	machineType := config.HypervisorMachineType
	if machineType == "" {
		machineType = defaultIchMachineType
	}

	ich := ichArchBase{
			machineType:           machineType,
			kernelParams:          kernelParams,	
	}

	return ich
}

func (ich *ichArchBase) kernelParameters(debug bool) []Param {
	
	return ich.kernelParams
}

func (ich *ichArchBase) ichPath() (string, error) {
	
	return defaultIchPath, nil
}



func (ich *ichArchBase) capabilities() types.Capabilities {
	var caps types.Capabilities
	//caps.SetFsSharingUnsupported()
	return caps
}

func (ich *ichArchBase) appendMemory(memoryMb uint32, path string) (govmmIch.Memory, error) {
	
	mem := fmt.Sprintf("%dM", memoryMb)
	
	memory := govmmIch.Memory{
		Size:   mem,
		Path:   path,
	}

	return memory, nil
}

func (ich *ichArchBase) appendProcessors(vcpu uint32) (govmmIch.VCPU, error) {
	
	vcpur := govmmIch.VCPU {
		Size:   vcpu,
	}

	return vcpur, nil
}

func (ich *ichArchBase) appendImage(devices []govmmIch.Device, path string) ([]govmmIch.Device, error) {
	devices = append(devices,
		govmmIch.DiskDevice{
			Path:          path,
		},
	)

	return devices, nil
}
func (ich *ichArchBase) appendVirtualFilesystem(devices []govmmIch.Device, tag string, path string) ([]govmmIch.Device, error) {
	devices = append(devices,
		govmmIch.VirtioFSDevice{
			Tag:		   tag,
			Path:          path,
			NumQueues:	   1,
			QueueSize:	   512,
		},
	)

	return devices, nil
}

func (ich *ichArchBase) appendSerialConsole(devices []govmmIch.Device, consoletype string) ([]govmmIch.Device, error) {
	
	validConsoleType := "tty"
	if(consoletype == "off" || consoletype == "null" ||
		consoletype == "tty") {
		validConsoleType = consoletype
		}
	if(strings.HasPrefix(consoletype, "file=")) {
		validConsoleType = consoletype	
	}
	devices = append(devices,
		govmmIch.SerialConsoleDevice{
			ConsoleType:	validConsoleType,
		},
	)

	return devices, nil
}
func (ich *ichArchBase) appendVirtioConsole(devices []govmmIch.Device, consoletype string) ([]govmmIch.Device, error) {
	
	validConsoleType := "null"
	if(consoletype == "off" || consoletype == "null" ||
		consoletype == "tty") {
		validConsoleType = consoletype
		}
	if(strings.HasPrefix(consoletype, "file=")) {
		validConsoleType = consoletype	
	}
	devices = append(devices,
		govmmIch.VirtioConsoleDevice{
			ConsoleType:	validConsoleType,
		},
	)

	return devices, nil
}
 
func (ich *ichArchBase) appendApiSocket(devices []govmmIch.Device, apisocket string) ([]govmmIch.Device, error) {
	
	devices = append(devices,
		govmmIch.ApiEndpointDevice{
			ApiSocket:	apisocket,
		},
	)

	return devices, nil
}

func (ich *ichArchBase) appendHybridVSock(devices []govmmIch.Device, vsock types.HybridVSock) ([]govmmIch.Device, error) {
	devices = append(devices,
		govmmIch.HybridVSOCKDevice{
			Path:          vsock.UdsPath,
			Port:		   vsock.Port,
		},
	)

	return devices, nil

}

func (ich *ichArchBase) appendNetwork(devices []govmmIch.Device, endpoint Endpoint) ([]govmmIch.Device, error) {
	d, err := ich.genericNetwork(endpoint, ich.vhost, ich.nestedRun, ich.networkIndex)
	if err != nil {
		return devices, fmt.Errorf("Failed to append network %v", err)
	}
	ich.networkIndex++
	devices = append(devices, d)
	return devices, nil
}

func (ich *ichArchBase) appendVnic(devices []govmmIch.Device, macAddress string) ([]govmmIch.Device, error) {
	d := govmmIch.NetDevice{
			Type:          govmmIch.TAP,
			ID:            fmt.Sprintf("network-%d", ich.networkIndex),
			IFName:        fmt.Sprintf("tap-%d", ich.networkIndex),
			MACAddress:    macAddress,
	}
	ich.networkIndex++
	devices = append(devices, d)
	return devices, nil
}

func  (ich *ichArchBase)  genericNetwork(endpoint Endpoint, vhost, nestedRun bool, index int) (govmmIch.NetDevice, error) {
	var d govmmIch.NetDevice
	switch ep := endpoint.(type) {
	case *VethEndpoint, *BridgedMacvlanEndpoint, *IPVlanEndpoint:
		netPair := ep.NetworkPair()
		d = govmmIch.NetDevice{
			Type:          networkModelToIchType(netPair.NetInterworkingModel),
			ID:            fmt.Sprintf("network-%d", index),
			IFName:        netPair.TAPIface.Name,
			MACAddress:    netPair.TAPIface.HardAddr,
			VHost:         vhost,
		}
	case *MacvtapEndpoint:
		d = govmmIch.NetDevice{
			Type:          govmmIch.MACVTAP,
			ID:            fmt.Sprintf("network-%d", index),
			IFName:        ep.Name(),
			MACAddress:    ep.HardwareAddr(),
			VHost:         vhost,
		}
	default:
		return govmmIch.NetDevice{}, fmt.Errorf("Unknown type for endpoint")
	}

	return d, nil
}

func networkModelToIchType(model NetInterworkingModel) govmmIch.NetDeviceType {
	switch model {
	case NetXConnectBridgedModel:
		return govmmIch.MACVTAP //TODO: We should rename MACVTAP to .NET_FD
	case NetXConnectMacVtapModel:
		return govmmIch.MACVTAP
	//case ModelEnlightened:
	// Here the Network plugin will create a VM native interface
	// which could be MacVtap, IpVtap, SRIOV, veth-tap, vhost-user
	// In these cases we will determine the interface type here
	// and pass in the native interface through
	default:
		//TAP should work for most other cases
		return govmmIch.TAP
	}
}

func (ich *ichArchBase) appendRNGDevice(devices []govmmIch.Device, rngDev config.RNGDev) ([]govmmIch.Device, error) {
	devices = append(devices,
		govmmIch.RngDevice {
			Filename: rngDev.Filename,
		},
	)

	return devices, nil
}

