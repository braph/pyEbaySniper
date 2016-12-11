#!/usr/bin/python3

# pyEbaySniper - timed bidding on ebay articles
# Copyright (C) 2016 Benjamin Abendroth
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import re
import sys
import math
import time
import shlex
import locale
import atexit
import requests
import threading
import traceback

import argparse
import argcomplete

from io import StringIO
from lxml import etree
from datetime import datetime, timedelta

from itertools import count
from collections import namedtuple

from prompt_toolkit import prompt
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import FileHistory

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support import expected_conditions as EC

program = 'pyEbaySniper'
version = '0.1'
commands = {}  # available shell commands.
variables = {} # variables are stored here.
threads = []   # bid threads
log = None

# setup config variables
def setup_vars():
    reg_variable('USER',     'User for ebay')
    reg_variable('PASSWORD', 'Password for ebay')
    reg_variable('DRIVER',   'Driver to use with selenium', 'PhantomJS',
        validate=lambda v: v in ('Chrome', 'Firefox', 'PhantomJS')
    )
    reg_variable('LOCALE',   'Localization for numerics and monetary stuff',
        validate=lambda v: locale.setlocale(locale.LC_ALL, v)
    )
    reg_variable('BID_AHEAD_SECONDS', 'How many seconds before the actually specified time the bid should be placed',
        value=3, type=int
    )
    reg_variable('HISTORY',   'History file',
        os.path.expanduser("~/.ebay_hist")
    )
    #reg_variable('COOKIE_FILE', 'File for cookies. (Optional)',
    #    os.path.expandvars('/tmp/ebay-$USER-cookie')
    #)

    reg_variable('DEBUG', 'Print stacktraces', type=bool, value=0)
    reg_variable('LOGIN_URL', 'URL for ebay login page', 'https://signin.ebay.de/ws/eBayISAPI.dll?SignIn')
    reg_variable('LOGIN_URL_RE', 'RegEx to check if URL is a login page', 'https://signin.ebay.de')
    reg_variable('LOGIN_FIELD_PASS_RE', 'RegEx to find password input field in login page', 'passwor')
    reg_variable('LOGIN_FIELD_USER_RE', 'RegEx to find user input field in login page', 'e-mail')

def print_infos():
    print("\n%s version %s\n" % (program, version))

    if not get_variable('LOCALE'):
        print("LOCALE is unset")
        print("\tYou have to explicitly set the ebay locale.")
        print("\tUse 'set LOCALE <ebay locale>' to the locale of your ebay site.")
        print("\tKeep in mind that all input inside this shell will also be interpreted according to that locale.")
        print()

    try:
        get_login_credentials()
    except:
        print("Remember to set the login credentials")
        print("\tset USER <username>")
        print("\tset PASSWORD <password>")
        print()

def main(): 
    argp = argparse.ArgumentParser(prog=program, description='Automated bidding on eBay articles')
    argp.add_argument('--rc', metavar='FILE', help='Specify config file to read on startup',
        default=os.path.join(os.path.expanduser('~'), ".ebayrc")
    )
    argp.add_argument('--log', metavar='FILE', help='Specify log file',
        default=os.path.expanduser("~/.ebaylog")
    )
    argp.add_argument('file', metavar='FILE', nargs='*', help='Specify script files to execute')
    args = argp.parse_args()

    setup_vars()

    log = open(args.log, 'a')

    if os.path.exists(args.rc):
        shell_source(args.rc)

    if not args.file:
        print_infos()
        read_stdin()
    else:
        for f in args.file:
            shell_source(f)

def read_script(input_stream):
    while True:
        line = input_stream.readline()
        if not line: break
        process_line(line.rstrip())

def read_stdin():
    while True:
        try:
            if get_variable('HISTORY'):
                fileHistory = FileHistory(get_variable('HISTORY'))
            else:
                fileHistory = None

            line = prompt(program + " > ", history=fileHistory, completer=CommandCompleter())
            process_line(line)
        except EOFError:
            break

def process_line(cmdline):
    if not cmdline:
        return

    if cmdline.startswith('#'):
        return

    try:
        cmdline = cmdline.split(maxsplit=1)

        if not cmdline:
            return

        if len(cmdline) == 2:
            call_command(cmdline[0], cmdline[1])
        else:
            call_command(cmdline[0], '')

    except EOFError:
        sys.exit(0)
    except Exception as e:
        print(program+':', cmdline[0]+':', e)
        if get_variable('DEBUG'):
            traceback.print_exc(file=log)


class CommandCompleter(Completer):
    def __init__(self):
        self.completions = {}
        for name, func in commands.items():
            self.completions[name] = argcomplete.CompletionFinder(func.argparser)

    def complete_command_names(self, line):
        if not line:
            for command in self.completions.keys():
                yield Completion(command, 0)
        else:
            for command in self.completions.keys():
                if command.startswith(line):
                    yield Completion(command, -len(line))

    def get_completions(self, document, complete_event):
        l = document.current_line_before_cursor

        if not l:
            return self.complete_command_names(l)

        command, *arguments = l.split()

        if command in self.completions:  
            for state in count(start=0):
                completed_line = self.completions[command].rl_complete(l, state)
                if completed_line:
                    yield Completion( completed_line[len(l):], start_position=0 )
                else:
                    return

        else:
            for compl_command in self.completions.keys():
                if compl_command.startswith(command):
                    yield Completion( compl_command, start_position=-len(l) )



###
# Decorators for making functions behave like command line programs
###
def add_argument(*add_argument_args, **add_argument_kwargs):
    ''' Add an argparser argument inside argparsed_func. '''
    return (add_argument, add_argument_args, add_argument_kwargs)

def add_mutually_exclusive_group(*add_argument_calls):
    ''' Create mutually exclusive argument group inside argparsed_func. '''
    return (add_mutually_exclusive_group, add_argument_calls)

def argparse_type(f):
    ''' Wrapper function for using functions as argparse's type= parameter '''
    def new_f(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            raise argparse.ArgumentTypeError(str(e))
    return new_f

def argparsed_func(name, *argparse_cmds, ignore_unknown=False):
    '''
        Create commandline-like parameterized functions.
        Call them either with func('--param', 'value')
        or with func(cmdline="--param value")
    '''
    def decorate(f):
        def command_function(*args, cmdline=None):
            if (len(args) and cmdline):
                raise Exception("Please only provide *args or cmdline=")
            elif cmdline:
                arguments = shlex.split(cmdline, comments=True)
            else:
                arguments = args

            try:
                if command_function.ignore_unknown:
                    parsed_args = command_function.argparser.parse_known_args(arguments)
                else:
                    parsed_args = command_function.argparser.parse_args(arguments)

                if cmdline: # save our cmdline
                    parsed_args._cmdline = cmdline
                return f(parsed_args)

            except SystemExit as e:
                    return

        argparser = argparse.ArgumentParser(prog=name, description=f.__doc__)
        for cmd in argparse_cmds:
            if cmd[0] == add_argument:
                argparser.add_argument(*cmd[1], **cmd[2])
            elif cmd[0] == add_mutually_exclusive_group:
                group = argparser.add_mutually_exclusive_group()
                for subcmd in cmd[1]:
                    group.add_argument(*subcmd[1], **subcmd[2])

        command_function.name = name
        command_function.argparser = argparser
        command_function.description = f.__doc__
        command_function.ignore_unknown = ignore_unknown

        return command_function 
    return decorate 


###
# Functions for handling variables and commands
###
def reg_variable(name, description, value='', type=str, validate=None):
    ''' Register shell variable including other information '''
    v = namedtuple('ShellVar', ['name', 'description', 'value', 'type', 'validate'])
    v.name = name
    v.description = description
    v.value = value
    v.type = type
    v.validate = validate
    variables[name] = v

def get_variable_info(name):
    ''' Return variable info '''
    if name not in variables:
        raise Exception("Variable '{}' not found".format(name))

    return variables[name]

def get_variable(name):
    ''' Return value of variable '''
    return get_variable_info(name).value

def reg_command(name, aliases=[]):
    ''' Register function as command '''
    def decorate(f):
        commands[name] = f
        for alias in aliases:
            commands[alias] = f

        return f
    return decorate

def call_command(command, cmdline):
    ''' Call command with commandline '''
    if command not in commands:
        raise Exception("Command not found")

    commands[command](cmdline=cmdline)


###
# Common functions
###
def get_driver():
    ''' Return webdriver instance as specified in config '''
    args = {}
    if not get_variable('DEBUG'):
        args['service_log_path'] = os.devnull

    return { 'Chrome':    webdriver.Chrome,
             'Firefox':   webdriver.Firefox,
             'PhantomJS': webdriver.PhantomJS
           }[get_variable('DRIVER')](**args)

def get_as_etree(url):
    response = requests.get(url)
    parser = etree.HTMLParser()
    return etree.parse(StringIO(response.text), parser)

def read_timespan(ts):
    ''' Read sleep-like timespan, return it as seconds '''
    if not re.fullmatch('((\d+)([dwms]?))+', ts):
        raise ValueError("Invalid timespan: '{}'".format(ts))

    seconds = 0
    for amount, multiplier in re.findall('(\d+)([dwms]?)', ts):
        if   multiplier == 'w': seconds += int(amount)*60*60*24*7
        elif multiplier == 'd': seconds += int(amount)*60*60*24
        elif multiplier == 'h': seconds += int(amount)*60*60
        elif multiplier == 'm': seconds += int(amount)*60
        else:                   seconds += int(amount)
    return seconds

def read_datetime(dt):
    ''' Try to parse date in 3 different manners, return datetime '''
    try: return datetime.strptime(dt, "%d.%m.%Y %H:%M:%S")
    except ValueError: pass
    try: return datetime.strptime(dt, "%m/%d/%Y %H:%M:%S")
    except ValueError: pass
    try: return datetime.strptime(dt, "%Y-%m-%d %H:%M:%S")
    except ValueError: pass

    raise ValueError("Not a valid date: '{}'".format(dt))

def read_price(str_bid):
    ''' Read bid as string, return as float. Take care of localization '''
    return locale.atof(str_bid)

def write_price(float_bid):
    ''' Write out bid as localized string '''
    return locale.format('%.2f', float_bid)

def get_login_credentials():
    ''' Return user and password, die if these parameters are unset '''
    user, password = get_variable('USER'), get_variable('PASSWORD')
    if not user:     raise Exception('USER not set')
    if not password: raise Exception('PASSWORD not set')
    return user, password


### basic shell commands
@reg_command('help')
@argparsed_func('help',
    add_argument('what', metavar='WHAT', nargs='?')
)
def shell_help(args):
    ''' Show help for commands or variables '''
    if not args.what:
        func_to_names = {}
        for name, func in commands.items():
            try:
                func_to_names[func].append(name) 
            except KeyError:
                func_to_names[func] = [name]

        print("Available commands:\n")
        for func, names in func_to_names.items():
            print('  ', '|'.join(names)+':', func.description)
    elif args.what in commands:
        call_command(args.what, '--help')
    elif args.what in variables:
        print('Info:', get_variable_info(args.what).description)
        shell_set(args.what)
    else:
        raise Exception("'{}' is neither a command nor a variable".format(what))

@reg_command('quit', aliases=['exit'])
@argparsed_func('quit')
def shell_quit(args):
    ''' Quit the shell '''
    raise EOFError

@reg_command('set')
@argparsed_func('set',
    add_argument('name',  metavar='NAME',  nargs='?'),
    add_argument('value', metavar='VALUE', nargs='?')
)
def shell_set(args):
    ''' Set or get variable values '''
    if not args.name: # print all variables if nothing given
        for name in variables: shell_set(name)
    elif not args.value:
        print(args.name, '=', str(get_variable(args.name)))
    else:
        var = get_variable_info(args.name)

        if var.validate and not var.validate(args.value):
            raise Exception("Invalid value for '{}'".format(var.name))

        var.value = var.type(args.value)

@reg_command('list', aliases=['ls'])
@argparsed_func('list')
def shell_list(args):
    ''' List bid threads '''
    for t in threads:
        print(repr(t), "\n")

@reg_command('kill')
@argparsed_func('kill',
    add_argument('id', type=int)
)
def shell_kill(args):
    ''' Kill a bid thread '''
    try:
        threads[args.id].cancel()
    except IndexError:
        raise Exception("No such thread.")

@reg_command('reload')
@argparsed_func('reload',
    add_argument('id', type=int)
)
def shell_reload(args):
    ''' Update article infos of thread '''
    try:
        threads[args.id].article_infos.load()
    except IndexError:
        raise Exception("No such thread.")

@reg_command('source')
@argparsed_func('source',
    add_argument('file')
)
def shell_source(args):
    ''' Source a script file '''
    if args.file == '-':
        read_stdin()
    else:
        with open(args.file, 'r') as fh:
            read_script(fh)

@reg_command('bid')
@argparsed_func('bid',
    add_mutually_exclusive_group(
        add_argument('--now', dest='now', action='store_true',
            help='Place the bid immediately'),
        add_argument('--after', dest='after', metavar='TIMESPAN', type=argparse_type(read_timespan),
            help='Place bid after now + TIMESPAN. Format like /bin/sleep'),
        add_argument('--before', dest='before', metavar='TIMESPAN', type=argparse_type(read_timespan),
            help='Place the bid on ending time - TIMESPAN. Format like /bin/sleep'),
        add_argument('--on', dest='on', metavar='TIME',     type=argparse_type(read_datetime),
            help='Place the bid on TIME. Format dd.mm.yy HH:MM:SS')
    ),
    add_argument('--dry', dest='dry', action='count', default=0,
        help="Don't actually place the bid, but do the login though. If specified twice, also disable login"),
    add_argument('url',  metavar='URL',
        help='URL to article'),
    add_argument('bid', metavar='BID', type=argparse_type(read_price),
        help='Price to bid')
)
def shell_bid(args):
    ''' Place bid on an eBay article '''
    get_login_credentials() # w/o login information bid will not work, better die NOW

    if   args.before: start_time = timedelta(seconds=args.before)
    elif args.after:  start_time = datetime.now() + timedelta(seconds=args.after)
    elif args.on:     start_time = args.on
    else:             start_time = datetime.now()

    bid_thread = BidThread(len(threads), args.url, args.bid, start_time, args.dry)
    threads.append(bid_thread)
    bid_thread.start()


class BidThread(threading.Timer):
    def __init__(self, thread_id, url, bid, start_time, dry=False):
        self.thread_id = thread_id
        self.url = url
        self.bid = bid
        self.dry = dry

        # initialized fields with 'empty' values
        self.bid_datetime = datetime.fromtimestamp(0)
        self.article_infos = EbayArticleInfoPage(self.url)

        self.bidded = False
        self.error = None

        if isinstance(start_time, timedelta): # seconds relative to ending time
            self.bid_datetime = self.article_infos.ending_datetime - start_time
        else:
            self.bid_datetime = start_time

        seconds_to_start = math.floor((self.bid_datetime - datetime.now()).total_seconds())

        if (seconds_to_start > 300):
            seconds_to_start -= 120 # 120 seconds for login, blacing bid etc.
            threading.Timer.__init__(self, seconds_to_start, self.do_bid)
        else:
            threading.Timer.__init__(self, 0, self.do_bid)

        if (self.bid < self.article_infos.current_bid):
            print("Warning, your bid will fail: Current price is %2.f, your bid is %2.f" % (
                self.article_infos.current_bid, self.bid))


    def start(self):
        threading.Timer.start(self)
        print("Job setup\n", repr(self))

    def do_bid(self):
        try:
            driver = get_driver()

            if (self.dry < 2):
                self.log("Logging in ...")
                login_page = EbayLoginPage(driver)
                user, password = get_login_credentials()
                try:
                    login_page.login(user, password)
                except:
                    login_page.login(user, password) # try again if failed

            article_page = EbayArticleBidPage(driver, self.url)

            self.log("Entering bid ", write_price(self.bid), ('(dry)' if self.dry else ''), "...")
            if not self.dry:
                article_page.enter_bid( write_price(self.bid) )

            seconds_to_start = math.floor((self.bid_datetime - datetime.now()).total_seconds())
            seconds_to_start -= get_variable('BID_AHEAD_SECONDS')

            if (seconds_to_start > 0):
                self.log("Waiting {} seconds before confirming bid ...".format(seconds_to_start))
                time.sleep(seconds_to_start)

            try:
                self.log("Confirming bid ", ('(dry)' if self.dry else ''), "...")
                self.bidded = True
                if not self.dry:
                    article_page.confirm_bid()
                self.log("Bidding done")
            finally:
                if not self.dry:
                    time.sleep(5) # TODO: bid on something and analyze output.
                    with open('/tmp/ebay-dump', 'a') as dump_fh:
                        dump_fh.write('<!-- ')
                        dump_fh.write(driver.current_url)
                        dump_fh.write("-->\n")
                        dump_fh.write(driver.page_source)

        except Exception as e:
            self.log("Got Exception: " + str(e))
            raise
        finally:
            driver.quit()

    def get_status(self):
        if self.bidded:
            return "Done"
        elif self.is_alive():
            bidding_in = self.bid_datetime - datetime.now()
            if bidding_in.total_seconds() < 0:
                return "Bidding now"
            else:
                bidding_in = str(bidding_in).split('.', 2)[0]
                return "Waiting (" + bidding_in + ")"
        else:
            return "Cancelled"

    def __repr__(self):
        return "{}: {}\n  Ending Date: {}\n  Bid Date: {}\n  Current Bid: {}\n  Bid: {}\n  Status: {}".format(
            self.thread_id,
            self.article_infos.title,
            self.article_infos.ending_datetime.strftime("%d.%m.%Y %H:%M:%S"),
            self.bid_datetime.strftime("%d.%m.%Y %H:%M:%S"),
            self.article_infos.currency + ' ' + write_price(self.article_infos.current_bid),
            self.article_infos.currency + ' ' + write_price(self.bid),
            self.get_status()
        )

    def log(self, *args):
        print(str(self.thread_id)+':', *args)

@reg_command('login')
@argparsed_func('login')
def shell_login(args):
    ''' log in on eBay '''
    user, password = get_login_credentials()
    try:
        driver = get_driver()
        login_page = EbayLoginPage(driver)
        login_page.login(user, password)
    finally:
        driver.quit()


##############################################################
# Ebay Pages
##############################################################
class EbayArticleInfoPage():
    def __init__(self, url):
        self.url = url
        self.load()

    def load(self):
        tree = get_as_etree(self.url)

        try:
            current_bid = tree.xpath('//span[@id="prcIsum_bidPrice"]')[0].text
            self.currency, bid = current_bid.split()
            self.current_bid = read_price(bid.replace('$', ''))
        except: # this is worse, but we can live without the bid either
            self.currency, self.current_bid = '???', -1.0

        self.title = ''
        try:
            for text in tree.xpath('//h1[@id="itemTitle"]')[0].itertext():
                self.title += text
        except: # well, we can live without a title ;)
            self.title = "Could not exctract article title. Consider to fix me"

        ending = ' '.join(
            filter(None,
                map(str.strip,
                    tree.xpath('//span[@class="vi-tm-left"]')[0].itertext())))

        ending = ending.lstrip('(')
        ending = ending.rstrip(')')
        ending = ending[0:ending.rindex(' ')]
        self.ending_datetime = datetime.strptime(ending, '%d. %b. %Y %H:%M:%S')
        #self.ending = dateparser.parse(ending, fuzzy=True)

    def __repr__(self):
        return "{}:\n\tEnding Date: {}\n\tCurrent Bid: {}\n".format(
            self.title,
            self.ending_datetime.strftime("%d.%m.%Y %H:%M:%S"),
            self.currency + ' ' + write_price(self.current_bid)
        )


class EbayArticleBidPage():
    def __init__(self, driver, url):
        self.driver = driver
        self.url = url
        self.reset()

    def reset(self):
        self.driver.get(self.url)

    def enter_bid(self, bid):
        ''' Enter the price in the bid field - without confirmation '''
        self.driver.find_element_by_id('MaxBidId').send_keys(bid + "\n")

    def confirm_bid(self):
        ''' Presses the confirmation button '''
        try:
            confirm_button = WebDriverWait(self.driver, 5).until(
                EC.element_to_be_clickable((By.XPATH, '//a[contains(@id, "reviewBidSec_btn")]'))
            )
            confirm_button.click()
        except Exception as e:
            try:
                msg = self.driver.find_element_by_xpath('//p[contains(@class, "sm-md mi-er")]').text
            except:
                raise Exception("Could not confirm bid") from e

            raise Exception("Could not confirm bid: " + msg) from None

    def is_logged_in(self):
        ''' Check if you are logged in '''
        try:
            self.driver.find_element_by_class_name('gh-ug-guest')
            raise Exception("You are not logged in (guest)")
        except NoSuchElementException: pass


class EbayLoginPage():
    def __init__(self, driver):
        self.driver = driver

    def reset(self):
        ''' Opens eBay login page on driver '''
        self.driver.get(get_variable('LOGIN_URL'))

    def is_login_page_open(self):
        ''' Checks if eBay login page is open in driver '''
        return re.match(get_variable('LOGIN_URL_RE'), self.driver.current_url, re.I)

    def login(self, user, password):
        ''' Enters login credentials in current driver
            and checks if login succeeded '''
        self.reset()
        old_url = self.driver.current_url

        login_form_user_input = None
        login_form_pass_input = None

        for i in self.driver.find_elements_by_xpath('//input[@class="fld"]'):
            if not i.is_displayed():
                continue
            
            placeholder = i.get_attribute('placeholder')
            if placeholder:
                if re.match(get_variable('LOGIN_FIELD_PASS_RE'), placeholder, re.I):
                    login_form_pass_input = i
                elif re.match(get_variable('LOGIN_FIELD_USER_RE'), placeholder, re.I):
                    login_form_user_input = i

        if not login_form_user_input:
            raise Exception("Could not find user input field, try editing 'LOGIN_FIELD_USER_RE' variable")
        if not login_form_pass_input:
            raise Exception("Could not find password input field, try editing 'LOGIN_FIELD_USER_RE' variable")

        login_form_pass_input.send_keys(password)
        login_form_user_input.send_keys(user)
        login_form_user_input.submit()

        for i in range(5): # wait for new page
            if self.driver.current_url != old_url:
                break
            time.sleep(1)

        try: # check for error message
            error_msg = self.driver.find_element_by_xpath('//span[@class="sd-err"]')
            if error_msg.is_displayed():
                raise Exception("Login failed: " + error_msg.text)
        except NoSuchElementException: pass # good ;)

######################### unused #############################
#import json
#def load_cookies(driver):
#    open_login_page(driver)
#
#    print("Loading cookies ...")
#    with open(cookie_file, 'r') as cookie_fh:
#        for line in cookie_fh.readlines():
#            try:
#                for cookie in json.loads(line):
#                    try:
#                        driver.add_cookie(cookie)
#                    except Exception as e:
#                        print("Error:", e)
#            except Exception as e:
#                print("Error:", e)
#
#def save_cookies(driver):
#    print("Saving cookies ...")
#    with open(cookie_file, "w") as cookie_fh:
#        cookie_fh.write(json.dumps(driver.get_cookies()))
##############################################################

if __name__ == '__main__':
    main()
