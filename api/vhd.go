package api

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"text/template"
)

type VhdType int

const (
	VhdType_Unknown      VhdType = 0
	VhdType_Fixed        VhdType = 2
	VhdType_Dynamic      VhdType = 3
	VhdType_Differencing VhdType = 4
)

var VhdType_name = map[VhdType]string{
	VhdType_Unknown:      "Unknown",
	VhdType_Fixed:        "Fixed",
	VhdType_Dynamic:      "Dynamic",
	VhdType_Differencing: "Differencing",
}

var VhdType_value = map[string]VhdType{
	"unknown":      VhdType_Unknown,
	"fixed":        VhdType_Fixed,
	"dynamic":      VhdType_Dynamic,
	"differencing": VhdType_Differencing,
}

func (x VhdType) String() string {
	return VhdType_name[x]
}

func ToVhdType(x string) VhdType {
	if integerValue, err := strconv.Atoi(x); err == nil {
		return VhdType(integerValue)
	}

	return VhdType_value[strings.ToLower(x)]
}

func (d *VhdType) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(d.String())
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (d *VhdType) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		var i int
		err2 := json.Unmarshal(b, &i)
		if err2 == nil {
			*d = VhdType(i)
			return nil
		}

		return err
	}
	*d = ToVhdType(s)
	return nil
}

type VhdFormat int

const (
	VhdFormat_Unknown VhdFormat = 0
	VhdFormat_VHD     VhdFormat = 2 //extension ".vhd"
	VhdFormat_VHDX    VhdFormat = 3 //extension ".vhdx"
	VhdFormat_VHDSet  VhdFormat = 4 //extension ".vhds"
)

var VhdFormat_name = map[VhdFormat]string{
	VhdFormat_Unknown: "Unknown",
	VhdFormat_VHD:     "VHD",
	VhdFormat_VHDX:    "VHDX",
	VhdFormat_VHDSet:  "VHDSet",
}

var VhdFormat_value = map[string]VhdFormat{
	"unknown": VhdFormat_Unknown,
	"vhd":     VhdFormat_VHD,
	"vhdx":    VhdFormat_VHDX,
	"vhdset":  VhdFormat_VHDSet,
}

func (x VhdFormat) String() string {
	return VhdFormat_name[x]
}

func ToVhdFormat(x string) VhdFormat {
	if integerValue, err := strconv.Atoi(x); err == nil {
		return VhdFormat(integerValue)
	}

	return VhdFormat_value[strings.ToLower(x)]
}

func (d *VhdFormat) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(d.String())
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (d *VhdFormat) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		var i int
		err2 := json.Unmarshal(b, &i)
		if err2 == nil {
			*d = VhdFormat(i)
			return nil
		}

		return err
	}
	*d = ToVhdFormat(s)
	return nil
}

type vhd struct {
	Path                    string
	BlockSize               uint32
	LogicalSectorSize       uint32
	PhysicalSectorSize      uint32
	ParentPath              string
	FileSize                uint64
	Size                    uint64
	MinimumSize             uint64
	Attached                bool
	DiskNumber              int
	Number                  int
	FragmentationPercentage int
	Alignment               int
	DiskIdentifier          string
	VhdType                 VhdType
	VhdFormat               VhdFormat
}

type createVhdFromSourceArgs struct {
	Source   string
	SourceVm string
	VhdPath  string
}

var createVhdFromSourceTemplate = template.Must(template.New("CreateVhdFromSource").Parse(`
$ErrorActionPreference = 'Stop'

function Get-7ZipPath {
	if (Get-Command "7z" -ErrorAction SilentlyContinue) { return "7z" }
	elseif (test-path "$env:ProgramFiles\7-Zip\7z.exe") { return "$env:ProgramFiles\7-Zip\7z.exe" }
	elseif (test-path "${env:ProgramFiles(x86)}\7-Zip\7z.exe") { return "${env:ProgramFiles(x86)}\7-Zip\7z.exe" }
	else { return "" }
}

function Expand-Downloads($FolderPath, $TargetPath) {
	Push-Location $FolderPath
	$tempPath = join-path $FolderPath "temp"
	New-Item -ItemType Directory -Force -Path $tempPath

	try {
		$7zPath = Get-7ZipPath
		if (-not $7zPath) { throw "7z.exe needed" }
		get-item *.zip | % {
			$command = """$7zPath"" x ""$($_.FullName)"" -o""$tempPath"""
			& cmd.exe /C $command
		}

		get-item *.7z | % {
			$command = """$7zPath"" x ""$($_.FullName)"" -o""$tempPath"""
			& cmd.exe /C $command
		}

		get-item *.tar.gz | % {
			$command = """$7zPath"" x ""$($_.FullName)"" -so | ""$7zPath"" x -aoa -si -ttar -o""$tempPath"""
			& cmd.exe /C $command
		}

		get-item *.box | % {
			$command = """$7zPath"" x ""$($_.FullName)"" -so | ""$7zPath"" x -aoa -si -ttar -o""$tempPath"""
			& cmd.exe /C $command
		}

		get-item *.vhdx | % { Move-Item $_.FullName $TargetPath -Force }

		get-item *.vhd | % { Move-Item $_.FullName $TargetPath -Force }

		$sourceFolder = if (Test-Path "$tempPath\Virtual Hard Disks") { "$tempPath\Virtual Hard Disks" } else { $tempPath }
		Get-ChildItem -Path $sourceFolder -Force | Select-Object -First 1 | Move-Item -Destination $TargetPath
	}
	finally {
		Pop-Location
		Remove-Item $tempPath -Force -Recurse
	}
}

function Get-FileFromUri($Url, $FolderPath) {

	$req = [System.Net.HttpWebRequest]::Create($Url)
	$req.Method = "HEAD"
	$response = $req.GetResponse()
	$fUri = $response.ResponseUri
	$filename = [System.IO.Path]::GetFileName($fUri.LocalPath);
	$response.Close()

	$destination = (Get-Item -Path ".\" -Verbose).FullName
	if ($FolderPath) { $destination = $FolderPath }
	$destination = Join-Path $destination $filename
	$webclient = New-Object System.Net.webclient
	$webclient.downloadfile($fUri.AbsoluteUri, $destination)
}

function Test-Uri($Url) {
	$testUri = $Url -as [System.URI]
	return $null -ne $testUri.AbsoluteURI -and $testUri.Scheme -match '[http|https]'
}

$vhdPath = '{{.VhdPath}}'
$source = '{{.Source}}'
$sourceVm = '{{.SourceVm}}'

$tempPathDirectory = $vhdPath + "_temp"
New-Item -ItemType Directory -Force -Path $tempPathDirectory
Push-Location $tempPathDirectory

try {
	if ($sourceVm) {
		Export-VM -Name $sourceVm -Path $tempPathDirectory
		Expand-Downloads -FolderPath $tempPathDirectory\@sourceVm -TargetPath $vhdPath
	}
	elseif ($source) {

		if (Test-Uri -Url $source) {
			Get-FileFromUri -Url $source -FolderPath $tempPathDirectory
		}
		else {
			Copy-Item $source $tempPathDirectory -Force
		}

		Expand-Downloads -FolderPath $tempPathDirectory -TargetPath $vhdPath
	}
}
finally {
	Pop-Location
	Remove-Item $tempPathDirectory -Force -Recurse
}
`))

func (c *HypervClient) CreateVhdFromSource(path string, source string, sourceVm string) (err error) {

	err = c.runFireAndForgetScript(createVhdFromSourceTemplate, createVhdFromSourceArgs{
		Source:   source,
		SourceVm: sourceVm,
		VhdPath:  path,
	})

	return err
}

type createNewVhdArgs struct {
	SourceDisk int
	VhdJson    string
}

var createNewVhdTemplate = template.Must(template.New("CreateNewVhd").Parse(`
$ErrorActionPreference = 'Stop'

Import-Module Hyper-V
$sourceDisk = {{.SourceDisk}}
$vhd = '{{.VhdJson}}' | ConvertFrom-Json
$vhdType = [Microsoft.Vhd.PowerShell.VhdType]$vhd.VhdType

$NewVhdArgs = @{ }
$NewVhdArgs.Path = $vhd.Path

if ($sourceDisk) {
	$NewVhdArgs.SourceDisk = $sourceDisk
}
elseif ($vhdType -eq [Microsoft.Vhd.PowerShell.VhdType]::Differencing) {
	$NewVhdArgs.Differencing = $true
	$NewVhdArgs.ParentPath = $vhd.ParentPath
}
else {
	if ($vhdType -eq [Microsoft.Vhd.PowerShell.VhdType]::Dynamic) {
		$NewVhdArgs.Dynamic = $true
	}
	elseif ($vhdType -eq [Microsoft.Vhd.PowerShell.VhdType]::Fixed) {
		$NewVhdArgs.Fixed = $true
	}

	if ($vhd.Size -gt 0) {
		$NewVhdArgs.SizeBytes = $vhd.Size
	}

	if ($vhd.BlockSize -gt 0) {
		$NewVhdArgs.BlockSizeBytes = $vhd.BlockSize
	}

	if ($vhd.LogicalSectorSize -gt 0) {
		$NewVhdArgs.LogicalSectorSizeBytes = $vhd.LogicalSectorSize
	}

	if ($vhd.PhysicalSectorSize -gt 0) {
		$NewVhdArgs.PhysicalSectorSizeBytes = $vhd.PhysicalSectorSize
	}
}

New-VHD @NewVhdArgs
`))

func (c *HypervClient) CreateNewVhd(path string, sourceDisk int, vhdType VhdType, parentPath string, size uint64, blockSize uint32, logicalSectorSize uint32, physicalSectorSize uint32) (err error) {
	vhdJson, err := json.Marshal(vhd{
		Path:               path,
		VhdType:            vhdType,
		ParentPath:         parentPath,
		Size:               size,
		BlockSize:          blockSize,
		LogicalSectorSize:  logicalSectorSize,
		PhysicalSectorSize: physicalSectorSize,
	})

	err = c.runFireAndForgetScript(createNewVhdTemplate, createNewVhdArgs{
		SourceDisk: sourceDisk,
		VhdJson:    string(vhdJson),
	})

	return err
}

func (c *HypervClient) CreateVhd(path string, source string, sourceVm string, sourceDisk int, vhdType VhdType, parentPath string, size uint64, blockSize uint32, logicalSectorSize uint32, physicalSectorSize uint32) (err error) {
	if len(source) > 0 || len(sourceVm) > 0 {
		return c.CreateVhdFromSource(path, source, sourceVm)
	}

	return c.CreateNewVhd(path, sourceDisk, vhdType, parentPath, size, blockSize, logicalSectorSize, physicalSectorSize)
}

type resizeVhdArgs struct {
	Path string
	Size uint64
}

var resizeVhdTemplate = template.Must(template.New("ResizeVhd").Parse(`
$ErrorActionPreference = 'Stop'
$vhd = Get-VHD -Path '{{.Path}}'
if ($vhd.Size -ne {{.Size}}){
	Resize-VHD -Path '{{.Path}}' -SizeBytes {{.Size}}
}
`))

func (c *HypervClient) ResizeVhd(path string, size uint64) (err error) {
	err = c.runFireAndForgetScript(resizeVhdTemplate, resizeVhdArgs{
		Path: path,
		Size: size,
	})

	return err
}

type getVhdArgs struct {
	Path string
}

var getVhdTemplate = template.Must(template.New("GetVhd").Parse(`
$ErrorActionPreference = 'Stop'
$path='{{.Path}}'

$vhdObject = $null
if (Test-Path $path) {
	$vhdObject = Get-VHD -path $path | %{ @{
		Path=$_.Path;
		BlockSize=$_.BlockSize;
		LogicalSectorSize=$_.LogicalSectorSize;
		PhysicalSectorSize=$_.PhysicalSectorSize;
		ParentPath=$_.ParentPath;
		FileSize=$_.FileSize;
		Size=$_.Size;
		MinimumSize=$_.MinimumSize;
		Attached=$_.Attached;
		DiskNumber=$_.DiskNumber;
		Number=$_.Number;
		FragmentationPercentage=$_.FragmentationPercentage;
		Alignment=$_.Alignment;
		DiskIdentifier=$_.DiskIdentifier;
		VhdType=$_.VhdType;
		VhdFormat=$_.VhdFormat;
	}}
}

if ($vhdObject){
	$vhd = ConvertTo-Json -InputObject $vhdObject
	$vhd
} else {
	"{}"
}
`))

func (c *HypervClient) GetVhd(path string) (result vhd, err error) {
	err = c.runScriptWithResult(getVhdTemplate, getVhdArgs{
		Path: path,
	}, &result)

	return result, err
}

type deleteVhdArgs struct {
	Path string
}

var deleteVhdTemplate = template.Must(template.New("DeleteVhd").Parse(`
$ErrorActionPreference = 'Stop'
if (Test-Path -Path '{{.Path}}') {
	Remove-Item -Path '{{.Path}}' -Force
}
`))

func (c *HypervClient) DeleteVhd(path string) (err error) {
	err = c.runFireAndForgetScript(deleteVhdTemplate, deleteVhdArgs{
		Path: path,
	})

	return err
}
