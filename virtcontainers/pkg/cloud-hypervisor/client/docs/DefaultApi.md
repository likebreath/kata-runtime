# \DefaultApi

All URIs are relative to *http://localhost/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**BootVM**](DefaultApi.md#BootVM) | **Put** /vm.boot | Boot the previously created VM instance.
[**CreateVM**](DefaultApi.md#CreateVM) | **Put** /vm.create | Create the cloud-hypervisor Virtual Machine (VM) instance. The instance is not booted, only created.
[**DeleteVM**](DefaultApi.md#DeleteVM) | **Put** /vm.delete | Delete the cloud-hypervisor Virtual Machine (VM) instance.
[**PauseVM**](DefaultApi.md#PauseVM) | **Put** /vm.pause | Pause a previously booted VM instance.
[**RebootVM**](DefaultApi.md#RebootVM) | **Put** /vm.reboot | Reboot the VM instance.
[**ResumeVM**](DefaultApi.md#ResumeVM) | **Put** /vm.resume | Resume a previously paused VM instance.
[**ShutdownVM**](DefaultApi.md#ShutdownVM) | **Put** /vm.shutdown | Shut the VM instance down.
[**ShutdownVMM**](DefaultApi.md#ShutdownVMM) | **Put** /vmm.shutdown | Shuts the cloud-hypervisor VMM.
[**VmInfoGet**](DefaultApi.md#VmInfoGet) | **Get** /vm.info | Returns general information about the cloud-hypervisor Virtual Machine (VM) instance.
[**VmmInfoGet**](DefaultApi.md#VmmInfoGet) | **Get** /vmm.info | Returns general information about the cloud-hypervisor Virtual Machine Monitor (VMM).



## BootVM

> BootVM(ctx, )
Boot the previously created VM instance.

### Required Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CreateVM

> CreateVM(ctx, vmConfig)
Create the cloud-hypervisor Virtual Machine (VM) instance. The instance is not booted, only created.

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**vmConfig** | [**VmConfig**](VmConfig.md)| The VM configuration | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## DeleteVM

> DeleteVM(ctx, )
Delete the cloud-hypervisor Virtual Machine (VM) instance.

### Required Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## PauseVM

> PauseVM(ctx, )
Pause a previously booted VM instance.

### Required Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## RebootVM

> RebootVM(ctx, )
Reboot the VM instance.

### Required Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ResumeVM

> ResumeVM(ctx, )
Resume a previously paused VM instance.

### Required Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ShutdownVM

> ShutdownVM(ctx, )
Shut the VM instance down.

### Required Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ShutdownVMM

> ShutdownVMM(ctx, )
Shuts the cloud-hypervisor VMM.

### Required Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## VmInfoGet

> VmInfo VmInfoGet(ctx, )
Returns general information about the cloud-hypervisor Virtual Machine (VM) instance.

### Required Parameters

This endpoint does not need any parameter.

### Return type

[**VmInfo**](VmInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## VmmInfoGet

> VmmInfo VmmInfoGet(ctx, )
Returns general information about the cloud-hypervisor Virtual Machine Monitor (VMM).

### Required Parameters

This endpoint does not need any parameter.

### Return type

[**VmmInfo**](VmmInfo.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)
