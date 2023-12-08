import "pe"

rule carbon_metadata
{
	meta:
		author = "ESET Research"
		date = "2017-03-30"
		description = "Turla Carbon malware"
		reference = "https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/"
		source = "https://github.com/eset/malware-ioc/"
		contact = "github@eset.com"
		license = "BSD 2-Clause"
		os = "windows"
		filetype = "executable"

	condition:
		(pe.version_info["InternalName"] contains "SERVICE.EXE" or pe.version_info["InternalName"] contains "MSIMGHLP.DLL" or pe.version_info["InternalName"] contains "MSXIML.DLL") and pe.version_info["CompanyName"] contains "Microsoft Corporation"
}
