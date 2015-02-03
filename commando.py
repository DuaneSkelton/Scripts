import sys
import os
import types

##############################################################################
# This is the parser
# Looks for args of the form /name:value and adds/sets the options dictionary 
# entry dict[name] = value
# If arg has no leading / then the name is set the arg and the value is set 
# to true
def parseOptions(options, args):
    for arg in args:
        if arg.startswith('/'):
            # Try to partition on the : or the +. The tupples
            # will have empty part and empty value if either fails
            name, part, value = arg[1:].partition(':')
            if part != ":":
                name, part, value = arg[1:].partition('+')

            # print "%s %s %s" % (name, part, value)

            # Simple case name:value
            if part == ":":
                options[name] = value
            # List case, where name+value implies support for multiple
            # /name+valueN to make a list of values for the /name
            elif part == "+":
                if name in options.keys():
                    # The existing instance of name is a string (we already
                    # found a /name:value) so we need to turn the string
                    # into a list
                    if type(options[name]) == types.StringType:
                        values = []
                        values.append(options[name])
                        values.append(value)
                        options[name] = values
                    # We can assume we already made the dict entry a list 
                    # of values so just append
                    else:
                        options[name].append(value)
                # No entry in the dict, and the '+' implies add to list
                # so make a new list with the value
                else:
                    options[name] = []
                    options[name].append(value)
            # handle the case of a /name with no value
            else:
                options[arg[1:]] = ""
        # handle the case of a arg with no leading /
        else:
            options[arg] = ""

    return options

def Help():
    help = \
    "Parses all entries in arg list and creates a dictionary as follows:\n" \
    "\n" \
    "If the arg is a single token, it is used as a key and the dict[name]\n" \
    "is set to an empty string\n" \
    "\n" \
    "If the arg is a single token with a leading /, it is used as a key\n" \
    "and the dict[name] is set to an empty string\n" \
    "\n" \
    "If the arg is of the form /name:value, the dict[name] is set to the\n" \
    "the value as a string. Successive references to /name:other will \n" \
    "replace the previous value with the specified value\n" \
    "\n" \
    "If the arg is of the form /name+value, the value will be appended\n" \
    "the list in dict[name]. If the current value of dict[name] is a string\n" \
    "the string is promoted to a list and the old and new values are \n" \
    "placed in the list. This lets you do /name:value1 and /name+value2\n" \
    "to make a list of options in a single dictionary entry, i.e. \n" \
    "dict[name] = [value1, value2]\n" \
    "\n" \
    "The caller can use this function generically - it is not expected that you \n" \
    "must pass sys.argv. You could grab required args and use this function\n" \
    "for optional args. For example your command line could look like\n" \
    "\n" \
    "\t>command required1 required2 /option1:value1 /option2:value2\n" \
    "\n" \
    "In such a case you would call this function with sys.argv[3:]\n" \
    "\n"
    return help


##############################################################################
# This is the main code - you can call this to check that the parser is doing
# what you want it to do
def main():
    if len(sys.argv) == 1:
        print Help()
    elif sys.argv[1] == "/?" or sys.argv[1] == "help":
        print Help()
    else:
        options = { 'command':sys.argv[0] }
        try:
            parseOptions(options, sys.argv[1:])
            for opt in options:
                print "%s = %s" % (opt, options[opt])
        except Exception as e:
            print ('Parse error -- %s') % (e)


if __name__ == '__main__':
   main()
