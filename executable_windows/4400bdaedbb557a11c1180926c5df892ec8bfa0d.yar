rule APT_Neuron2_Loader_Strings
{
	meta:
		description = "Rule for detection of Neuron2 based on strings within the loader"
		author = "NCSC"
		referer = "https://otx.alienvault.com/pulse/5dad718fa5ec6c21e85c1c66"
		hash = "51616b207fde2ff1360a1364ff58270e0d46cf87a4c0c21b374a834dd9676927"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "dcom_api" ascii
		$ = "http://*:80/OWA/OAB/" ascii
		$ = "https://*:443/OWA/OAB/" ascii
		$ = "dcomnetsrv.cpp" wide
		$ = "dcomnet.dll" ascii
		$ = "D:\\Develop\\sps\\neuron2\\x64\\Release\\dcomnet.pdb" ascii

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and 2 of them
}
