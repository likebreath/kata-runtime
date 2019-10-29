#
# Makefile
# Carlos Venegas, 2019-10-14 17:01
#

all: clean-generated-code
	# TODO curl
	cp ~/cloud-hypervisor/vmm/src/api/openapi/cloud-hypervisor.yaml .
	java -jar openapi-generator-cli.jar generate -i cloud-hypervisor.yaml -g go -o ./client

clean-generated-code:
	rm "./client" -rf

get-openapi-cli:
	./get-openapi-generator-cli.sh
