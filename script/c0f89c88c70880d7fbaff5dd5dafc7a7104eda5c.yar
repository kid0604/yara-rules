rule INDICATOR_TOOL_PET_Peirates
{
	meta:
		author = "ditekSHen"
		description = "Detects Kubernetes penetration tool Peirates"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "DeprecatedServiceAccount" fullword ascii
		$s2 = "LivenessProbe" fullword ascii
		$s3 = "\\t\\tkubectl expose rs nginx --port=80 --target-port=8000" ascii
		$s4 = "\\t\\tkubectl run hazelcast --image=hazelcast --port=5701" ascii
		$s5 = "COMPREPLY[$i]=${COMPREPLY[$i]#\"$colon_word\"}" ascii
		$s6 = "%*polymorphichelpers.HistoryViewerFunc" ascii
		$s7 = "ListenAndServeTLS" ascii
		$s8 = "DownwardAPI" ascii
		$s9 = "; plural=(n%10==1 && n%100!=11 ? 0 : n != 0 ? 1 : 2);proto:" ascii
		$s10 = "name: attack-" ascii

	condition:
		uint16(0)==0x457f and 9 of them
}
