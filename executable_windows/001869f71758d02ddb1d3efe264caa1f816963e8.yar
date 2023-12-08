import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_VM_Evasion_VirtDrvComb
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing combination of virtualization drivers"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "prleth.sys" ascii wide
		$p2 = "prlfs.sys" ascii wide
		$p3 = "prlmouse.sys" ascii wide
		$p4 = "prlvideo.sys	" ascii wide
		$p5 = "prltime.sys" ascii wide
		$p6 = "prl_pv32.sys" ascii wide
		$p7 = "prl_paravirt_32.sys" ascii wide
		$vb1 = "VBoxMouse.sys" ascii wide
		$vb2 = "VBoxGuest.sys" ascii wide
		$vb3 = "VBoxSF.sys" ascii wide
		$vb4 = "VBoxVideo.sys" ascii wide
		$vb5 = "vboxdisp.dll" ascii wide
		$vb6 = "vboxhook.dll" ascii wide
		$vb7 = "vboxmrxnp.dll" ascii wide
		$vb8 = "vboxogl.dll" ascii wide
		$vb9 = "vboxoglarrayspu.dll" ascii wide
		$vb10 = "vboxoglcrutil.dll" ascii wide
		$vb11 = "vboxoglerrorspu.dll" ascii wide
		$vb12 = "vboxoglfeedbackspu.dll" ascii wide
		$vb13 = "vboxoglpackspu.dll" ascii wide
		$vb14 = "vboxoglpassthroughspu.dll" ascii wide
		$vb15 = "vboxservice.exe" ascii wide
		$vb16 = "vboxtray.exe" ascii wide
		$vb17 = "VBoxControl.exe" ascii wide
		$vp1 = "vmsrvc.sys" ascii wide
		$vp2 = "vpc-s3.sys" ascii wide
		$vw1 = "vmmouse.sys" ascii wide
		$vw2 = "vmnet.sys" ascii wide
		$vw3 = "vmxnet.sys" ascii wide
		$vw4 = "vmhgfs.sys" ascii wide
		$vw5 = "vmx86.sys" ascii wide
		$vw6 = "hgfs.sys" ascii wide

	condition:
		uint16(0)==0x5a4d and ((2 of ($p*) and (2 of ($vb*) or 2 of ($vp*) or 2 of ($vw*))) or (2 of ($vb*) and (2 of ($p*) or 2 of ($vp*) or 2 of ($vw*))) or (2 of ($vp*) and (2 of ($p*) or 2 of ($vb*) or 2 of ($vw*))) or (2 of ($vw*) and (2 of ($p*) or 2 of ($vb*) or 2 of ($vp*))))
}
