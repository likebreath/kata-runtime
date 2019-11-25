#!/bin/bash
# Copyright (c) 2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

cli_version=4.1.3
jar_url="http://central.maven.org/maven2/org/openapitools/openapi-generator-cli/${cli_version}/openapi-generator-cli-${cli_version}.jar"

curl -L "${jar_url}" --output openapi-generator-cli.jar
