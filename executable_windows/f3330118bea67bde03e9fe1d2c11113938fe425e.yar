import "pe"

rule HKTL_NET_GUID_Lime_RAT_alt_1
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Lime-RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-30"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "e58ac447-ab07-402a-9c96-95e284a76a8d" ascii wide
		$typelibguid0up = "E58AC447-AB07-402A-9C96-95E284A76A8D" ascii wide
		$typelibguid1lo = "8fb35dab-73cd-4163-8868-c4dbcbdf0c17" ascii wide
		$typelibguid1up = "8FB35DAB-73CD-4163-8868-C4DBCBDF0C17" ascii wide
		$typelibguid2lo = "37845f5b-35fe-4dce-bbec-2d07c7904fb0" ascii wide
		$typelibguid2up = "37845F5B-35FE-4DCE-BBEC-2D07C7904FB0" ascii wide
		$typelibguid3lo = "83c453cf-0d29-4690-b9dc-567f20e63894" ascii wide
		$typelibguid3up = "83C453CF-0D29-4690-B9DC-567F20E63894" ascii wide
		$typelibguid4lo = "8b1f0a69-a930-42e3-9c13-7de0d04a4add" ascii wide
		$typelibguid4up = "8B1F0A69-A930-42E3-9C13-7DE0D04A4ADD" ascii wide
		$typelibguid5lo = "eaaeccf6-75d2-4616-b045-36eea09c8b28" ascii wide
		$typelibguid5up = "EAAECCF6-75D2-4616-B045-36EEA09C8B28" ascii wide
		$typelibguid6lo = "5b2ec674-0aa4-4209-94df-b6c995ad59c4" ascii wide
		$typelibguid6up = "5B2EC674-0AA4-4209-94DF-B6C995AD59C4" ascii wide
		$typelibguid7lo = "e2cc7158-aee6-4463-95bf-fb5295e9e37a" ascii wide
		$typelibguid7up = "E2CC7158-AEE6-4463-95BF-FB5295E9E37A" ascii wide
		$typelibguid8lo = "d04ecf62-6da9-4308-804a-e789baa5cc38" ascii wide
		$typelibguid8up = "D04ECF62-6DA9-4308-804A-E789BAA5CC38" ascii wide
		$typelibguid9lo = "8026261f-ac68-4ccf-97b2-3b55b7d6684d" ascii wide
		$typelibguid9up = "8026261F-AC68-4CCF-97B2-3B55B7D6684D" ascii wide
		$typelibguid10lo = "212cdfac-51f1-4045-a5c0-6e638f89fce0" ascii wide
		$typelibguid10up = "212CDFAC-51F1-4045-A5C0-6E638F89FCE0" ascii wide
		$typelibguid11lo = "c1b608bb-7aed-488d-aa3b-0c96625d26c0" ascii wide
		$typelibguid11up = "C1B608BB-7AED-488D-AA3B-0C96625D26C0" ascii wide
		$typelibguid12lo = "4c84e7ec-f197-4321-8862-d5d18783e2fe" ascii wide
		$typelibguid12up = "4C84E7EC-F197-4321-8862-D5D18783E2FE" ascii wide
		$typelibguid13lo = "3fc17adb-67d4-4a8d-8770-ecfd815f73ee" ascii wide
		$typelibguid13up = "3FC17ADB-67D4-4A8D-8770-ECFD815F73EE" ascii wide
		$typelibguid14lo = "f1ab854b-6282-4bdf-8b8b-f2911a008948" ascii wide
		$typelibguid14up = "F1AB854B-6282-4BDF-8B8B-F2911A008948" ascii wide
		$typelibguid15lo = "aef6547e-3822-4f96-9708-bcf008129b2b" ascii wide
		$typelibguid15up = "AEF6547E-3822-4F96-9708-BCF008129B2B" ascii wide
		$typelibguid16lo = "a336f517-bca9-465f-8ff8-2756cfd0cad9" ascii wide
		$typelibguid16up = "A336F517-BCA9-465F-8FF8-2756CFD0CAD9" ascii wide
		$typelibguid17lo = "5de018bd-941d-4a5d-bed5-fbdd111aba76" ascii wide
		$typelibguid17up = "5DE018BD-941D-4A5D-BED5-FBDD111ABA76" ascii wide
		$typelibguid18lo = "bbfac1f9-cd4f-4c44-af94-1130168494d0" ascii wide
		$typelibguid18up = "BBFAC1F9-CD4F-4C44-AF94-1130168494D0" ascii wide
		$typelibguid19lo = "1c79cea1-ebf3-494c-90a8-51691df41b86" ascii wide
		$typelibguid19up = "1C79CEA1-EBF3-494C-90A8-51691DF41B86" ascii wide
		$typelibguid20lo = "927104e1-aa17-4167-817c-7673fe26d46e" ascii wide
		$typelibguid20up = "927104E1-AA17-4167-817C-7673FE26D46E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
