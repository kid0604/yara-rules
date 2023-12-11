rule BypassUacDll_6
{
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
		os = "windows"
		filetype = "executable"

	strings:
		$s3 = "BypassUacDLL.dll" fullword wide
		$s4 = "AFX_IDP_COMMAND_FAILURE" fullword ascii

	condition:
		all of them
}
