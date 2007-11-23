# $Id$

load Debug/sysdns01g.dll
if {[string equal $tcl_platform(platform) windows]} {
	console show
	console eval {
		wm protocol . WM_DELETE_WINDOW exit
		wm title . "sysdns testbed"
		bind .console <Control-q> exit
	}
}
wm withdraw .
