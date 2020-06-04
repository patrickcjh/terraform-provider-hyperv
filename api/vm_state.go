package api

import (
	"text/template"
)

type startVmArgs struct {
	VmName string
}

var startVmTemplate = template.Must(template.New("StartVm").Parse(`
$ErrorActionPreference = 'Stop'

$vmName = '{{.VmName}}'

Start-VM -Name $vmName 
`))

func (c *HypervClient) StartVm(
	vmName string,
) (err error) {

	err = c.runFireAndForgetScript(startVmTemplate, startVmArgs{
		VmName: vmName,
	})

	return err
}

type stopVmArgs struct {
	VmName string
}

var stopVmTemplate = template.Must(template.New("StopVm").Parse(`
$ErrorActionPreference = 'Stop'

$vmName = '{{.VmName}}'

Stop-VM -Name $vmName -Force
`))

func (c *HypervClient) StopVm(
	vmName string,
) (err error) {

	err = c.runFireAndForgetScript(stopVmTemplate, stopVmArgs{
		VmName: vmName,
	})

	return err
}
