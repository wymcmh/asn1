#!/usr/bin/env python

# This is an asn.1 decoding tool that can parse the BER/DER stream, 
# display its message structure, field types, and values 
# without relying on the original protocol file.

# Author: Yameng Wu
# Date: 2018-05-16

from asn1tinydecoder import *
import string
import binascii
import traceback

# get tag type of node
def get_tag(der, (ixs, ixf, ixl)):
    tag_type = { 
            0:'UNIVERSAL',
            1:'APPLICTAION',
            2:'CONTEXT',
            3:'PRIVATE'
    }
    universal_type = {
            0x00:'BER_RESERVE',       0x01:'BOOLEAN',
            0x02:'INTEGER',           0x03:'BIT_STRING',
            0x04:'OCTET_STRING' ,     0x05:'NULL',
            0x06:'OBJECT_IDENTIFIER', 0x07:'ObjectDescripion',
            0x08:'EXTERNAL',          0x09:'REAL',
            0x0A:'ENUMERATED',        0x0B:'EMBEDDED_PDV', 
            0x0C:'UTF8String',        0x0D:'RELATIVE-OID',
            0x0E:'RESERVE',           0x0F:'RESERVE',
            0x10:'SEQUENCE',          0x11:'SET',
            0x12:'NumericString',     0x13:'PrintableString',
            0x14:'TeletexString',     0x15:'VideotexString',
            0x16:'IA5String',         0x17:'UTCTime',
            0x18:'GeneralizedTime',   0x19:'GraphicString',
            0x20:'VisibleString',     0x21:'GeneralString',
            0x22:'UniversalString',   0x23:'CHARACTER_STRING',
            0x24:'BMPString',         0x25:'RESERVE'
    }
    tag_class = ord(der[ixs]) >> 6
    tag_val = ord(der[ixs]) & 0x1f
    # get tag description
    if tag_class == 0:
        # universal tag
        type_desc = universal_type[tag_val]
    else:
        # user define tag
        type_desc = tag_type[tag_class] + '_' + str(tag_val)
    return type_desc

# type check
def is_group(der, (ixs, ixf, ixl)):
    return ord(der[ixs])&0x20 == 0x20

def is_printable(s):
    return all(c in string.printable for c in s)

def is_bcd(s):
    for c in s[:-1]:
        v = ord(c)
        if v&0xf0>0x90 or v&0x0f>0x09:
            return 0
    v = ord(s[-1])
    if v==0xff or (v&0xf0>0x90 and v&0xf0!=0xf0) or (v&0x0f>0x09 and v&0x0f!=0x0f):
        return 0
    return 1

# parse specific type
def get_ip(s):
    if len(s)!=5 or ord(s[0])!=4:
        return ''
    return '.'.join([str(ord[x]) for x in s[1:5]])

def get_oid(s):
    v = ord(s[0])
    v1 = int(v/40)
    v2 = v - v1*40
    r = str(v1) + '.' + str(v2)

    val = 0
    for c in s[1:]:
        v = ord(c)
        val = (val<<7) + (v&0x7f)
        if v&0x80 == 0x00:
            r = r + '.' + str(val)
            val = 0
    return r

def get_time(s):
    r = '20' + s
    return r

def get_boolean(s):
    if ord(s[0])==0:
	return 'false'
    return 'true'

# parse struct
def parse_der(der, is_bin=0):
    if not is_bin:
        der = der.decode('hex')

    r = ''
    node = asn1_node_root(der)
    fs = []
    try:
        while node:
#            print 'debug\tparse_der\tnode:', node
            tag = get_tag(der, node)
            if is_group(der, node):
                r = r + ('    '*len(fs)) + 'group ' + tag + '\n'
                fs.append(node)
                node = asn1_node_first_child(der, node)

            else:
                val = asn1_get_value(der, node)
                r = r + ('    '*len(fs)) + 'element ' + tag
                # just try to decode as ipv4
                ip = get_ip(val)
                if tag=='NULL':
                    r = r + ' null ' + '\n'
                elif tag=='BOOLEAN':
                    r = r + ' bool ' + get_boolean(val) + '\n'
                elif tag=='OBJECT_IDENTIFIER':
                    r = r + ' oid ' + get_oid(val) + '\n'
                elif tag=='UTCTime':
                    r = r + ' utc ' + get_time(val) + '\n'
                elif tag[-6:]=='String' or (len(val)>=3 and is_printable(val)):
                    r = r + ' str ' + val + '\n'
                elif tag=='INTEGER' or tag=='ENUMERATED' or len(val) <= 4:
                    r = r + ' int ' + str(bytestr_to_int(val)) + '\n'
                elif ip != '':
                    r = r + ' ipv4 ' + ip + '\n'
                elif is_bcd(val):
                    r = r + ' bcd ' + binascii.hexlify(val) + '\n'
                else:
                    # 'REAL', 'BIT_STRING', 'OCTET_STRING' or others
                    r = r + ' hex ' + binascii.hexlify(val) + '\n'

                node = asn1_node_next(der, node)
                if not asn1_node_is_child_of(fs[-1], node):
                    fs.pop()

    except IndexError:
        pass

    except Exception, e:
        traceback.print_exc()

    return r

# main
import sys

if __name__ == '__main__':
    der_file='msg_der.bin'
    is_bin=1
    if len(sys.argv)>=3:
        is_bin=int(sys.argv[2])
    if len(sys.argv)>=2:
        der_file = sys.argv[1]
    else:
        print 'Usage:\n\t%s der_file [is_bin = 1]\n' % sys.argv[0]
        exit(1)

    data = open(der_file).read()
    if is_bin:
        der = data
    else:
        # remove all blank,CR,LF char
        der = "".join(data.split())

    print parse_der(der, is_bin)

