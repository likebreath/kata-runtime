#
# Copyright (c) 2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

all: clean-generated-code
	java -jar openapi-generator-cli.jar generate -i cloud-hypervisor.yaml -g go -o ./client

update-yaml:
	curl -OL https://raw.githubusercontent.com/cloud-hypervisor/cloud-hypervisor/master/vmm/src/api/openapi/cloud-hypervisor.yaml

clean-generated-code:
	rm "./client" -rf

get-openapi-cli:
	./get-openapi-generator-cli.sh
