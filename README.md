
As part of our application process, we would like you to write a test

program that we could later discuss in your interview. The data you

send using the program will be used for further communication with

you. You can write your program in any programming language you

prefer, but you should be able to show and explain your solution later

in the interview. To connect to the server, you need the keys included

in this README.

 

The following pseudocode represents the program you need to write. It

is a full implementation with all required elements. It is written

with Python language syntax and semantics in mind, but it is not a

correct implementation and needs to be extended to actually run in a

Python interpreter. The main purpose of this pseudocode is to give you

an idea of what you need to develop.

 

 

# === BEGIN ===

conn = tls_connect("xxx.xxx.xxx.xxx:xxxx", cert, key)

authdata = ""

while true:

    args = conn.read().strip().split(' ')

    if args[0] == "HELO":

        conn.write("EHLO\n")

    elif args[0] == "ERROR":

        print("ERROR: " + " ".join(args[1:]))

        break

    elif args[0] == "POW":

        authdata, difficulty = args[1], args[2]

        while true:

            # generate short random string, server accepts all utf-8 characters,

            # except [\n\r\t ], it means that the suffix should not contain the

            # characters: newline, carriege return, tab and space

            suffix = random_string()

            cksum_in_hex = SHA1(authdata + suffix)

            # check if the checksum has enough leading zeros

            # (length of leading zeros should be equal to the difficulty)

            if cksum_in_hex.startswith("0"*difficulty):

                conn.write(suffix + "\n")

                break

    elif args[0] == "END":

        # if you get this command, then your data was submitted

        conn.write("OK\n")

        break

    # the rest of the data server requests are required to identify you

    # and get basic contact information

    elif args[0] == "NAME":

       # as the response to the NAME request you should send your full name

       # including first and last name separated by single space

       conn.write(SHA1(authdata + args[1]) + " " + "My name\n")

    elif args[0] == "MAILNUM":

       # here you specify, how many email addresses you want to send

       # each email is asked separately up to the number specified in MAILNUM

       conn.write(SHA1(authdata + args[1]) + " " + "2\n")

    elif args[0] == "MAIL1":

       conn.write(SHA1(authdata + args[1]) + " " + "my.name@example.com\n")

    elif args[0] == "MAIL2":

       conn.write(SHA1(authdata + args[1]) + " " + "my.name2@example.com\n")

    elif args[0] == "SKYPE":

       # here please specify your Skype account for the interview, or N/A

       # in case you have no Skype account

       conn.write(SHA1(authdata + args[1]) + " " + "my.name@example.com\n")

    elif args[0] == "BIRTHDATE":

       # here please specify your birthdate in the format %d.%m.%Y

       conn.write(SHA1(authdata + args[1]) + " " + "01.02.2017\n")

    elif args[0] == "COUNTRY":

       # country where you currently live and where the specified address is

       # please use only the names from this web site:

       #   https://www.countries-ofthe-world.com/all-countries.html

       conn.write(SHA1(authdata + args[1]) + " " + "Germany\n")

    elif args[0] == "ADDRNUM":

       # specifies how many lines your address has, this address should

       # be in the specified country

       conn.write(SHA1(authdata + args[1]) + " " + "2\n")

    elif args[0] == "ADDRLINE1":

       conn.write(SHA1(authdata + args[1]) + " " + "Long street 3\n")

    elif args[0] == "ADDRLINE2":

       conn.write(SHA1(authdata + args[1]) + " " + "32345 Big city\n")

conn.close()

# === END ===

#exasol
