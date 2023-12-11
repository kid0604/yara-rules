rule Stuxnet_MadeInPython
{
	meta:
		description = "Python has been used frequently by threat actors for compiling executable file with source code. I found python Stuxnet source code that can be executed with required dependencies. This rule is created in hopes to catch potental breakout of future Stuxnet."
		author = "Jin Kim"
		reference = "https://github.com/kenmueller/stuxnet"
		date = "2020-12-23"
		os = "windows,linux"
		filetype = "script"

	strings:
		$str1 = "old_infected_attributes = node_infected_attributes(graph)"
		$str2 = "NodeType.DISCONNECTED_COMPUTER"
		$str3 = "add_computer_nodes(graph, EdgeType.LOCAL_WIRELESS, router_node)"

	condition:
		any of them
}
