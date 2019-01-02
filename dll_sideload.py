# Quickly and sloppily put together IDAPython script to find potential DLL side-loading vulnerabilities. 
# Needs to be modified depending on the DLL you're going through as the operand may change. 
# Could also be modified to search the target OSes' file system for missing potentially missing DLL. 
#
# Author: Stephen Sims - @Steph3nSims

addr = SegByBase(SegByName(".text"))				 
end = SegEnd(addr)
results = []

i = 0

while addr < end and addr != BADADDR:
	for function_ea in Functions(SegStart(addr), SegEnd(end)):
                opnd = GetOpnd(addr, 0)
                
		if opnd == "cs:__imp_LoadLibraryExW":
                        
                        #if GetMnem(addr-2) == "xor" and GetCommentEx(addr-2, 0) == "dwFlags" or GetMnem(addr-12) == "xor" and GetCommentEx(addr-12, 0) == "dwFlags": 
                        if GetOpnd(PrevHead(addr), 1) == "800h" or GetOpnd(PrevHead(PrevHead(addr)), 1) == "800h" or  GetOpnd(PrevHead(PrevHead(PrevHead(addr))), 1) == "800h":
                                addr = NextAddr(addr)
                        else:
                                print "Address:  ", hex(addr)[2:11], GetDisasm(addr)
                                dll = GetDisasm(GetOperandValue(addr-9, 1))[12:-3]
                                print "DLL Name: ", dll
                                results.append([addr, dll])
                                i += 1
                                addr = NextAddr(addr)
		else:
			addr = NextAddr(addr)
				
print "\n%d total LoadLib's found!" % len(results)

if results != []:
	filename = str(GetInputFile())
	filename = filename.split(".")[0]
	f = open('c:\Temp\%s.txt' % filename, "w")
	f.write("Input File: %s\n" % GetInputFile().upper())
	f.write("----------\n\n")
	for a in results:
                if a[1] is "":
                        f.write("Address:  %x\nDLL Name: UNKNOWN\n\n" % (a[0]))
                else:
                        f.write("Address:  %x\nDLL Name: %s\n\n" % (a[0], a[1]))
	f.close()
	print "Results written to %s.txt" % filename
else:
	print "Fail!"
				
				
