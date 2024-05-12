# coding=utf-8
import hashlib
import struct

import frida
import sys

import zlib
from google.protobuf.internal import decoder
import subprocess


def decodebuf(data):
    process = subprocess.Popen([r'C:\ProgramData\chocolatey\lib\protoc\tools\bin\protoc.exe', '--decode_raw'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = error = None
    try:
        output, error = process.communicate(data)
    except OSError:
        pass
    finally:
        if process.poll() != 0:
            process.wait()
    return output


def b2hex(s): return ''.join(["%02X" % x for x in s]).strip()


def unpad(s): return s[0:(len(s) - s[-1])]


def on_message(message, data):
    if message['type'] == 'error':
        print("[!] " + message['stack'])
    elif message['type'] == 'send':
        payload = message['payload']
        if payload == 'bodybyte':
            print("##" + b2hex(data))
            if len(data) > 0x20:
                src = data
                nCur = 0
                if src[nCur] == struct.unpack('>B', b'\xbf')[0]:
                    nCur += 1
                nLenHeader = int(src[nCur]) >> 2
                print("包头长度: " + str(nLenHeader))
                bUseCompressed = (src[nCur] & 0x3 == 1)  # 包体是否使用压缩算法:01使用,02不使用
                print("是否压缩: " + str(bUseCompressed))
                nCur += 1
                nDecryptType = src[nCur] >> 4  # 解密算法(固定为AES解密): 05 aes解密 / 07 rsa解密
                print("加密类型: " + str(nDecryptType))
                nLenCookie = src[nCur] & 0xf  # cookie长度
                print("Cookie长度: " + str(nLenCookie))
                nCur += 1
                ver = struct.unpack('>i', src[nCur:nCur + 4])[0]  # ver
                print("当前VER: " + str(ver))
                nCur += 4
                uin = struct.unpack('>i', src[nCur:nCur + 4])[0]  # uin
                print("当前uin: " + str(uin))
                nCur += 4
                cookie_temp = src[nCur:nCur + nLenCookie]  # cookie
                nCur += nLenCookie
                (nCgi, nCur) = decoder._DecodeVarint(src, nCur)  # cgi type
                print("当前CGI : " + str(nCgi))
                (nLenProtobuf, nCur) = decoder._DecodeVarint(src, nCur)  # 压缩前protobuf长度
                print("压缩前protobuf长度 : " + str(nLenProtobuf))
                (nLenCompressed, nCur) = decoder._DecodeVarint(src, nCur)  # 压缩后protobuf长度
                print("压缩后protobuf长度 : " + str(nLenCompressed))
                # 最后还有几个字节
                print(str(nLenHeader - nCur) + " : " + b2hex(src[nCur:nLenHeader]))
                if nLenHeader - nCur == 9:
                    nCur += 2  # 过滤掉 00 0D
                    (nChecksum, nCur) = decoder._DecodeVarint(src, nCur)  # 压缩后protobuf长度
                    print("nChecksum : " + str(nChecksum))
                elif nLenHeader - nCur == 6:
                    RSAVER = struct.unpack('>B', src[nCur:nCur + 1])[0]
                    print("RSAVER : " + str(RSAVER))

        elif payload == 'comprocess_data':
            print(decodebuf(data))
        elif payload == 'aeskey':
            print(b2hex(data))
        elif payload == 'compressed':
            print('[*] ********* ready to decodebuffer')
            binhex = b2hex(data)

            if binhex.startswith("0A"):
                print(decodebuf(data))
            else:
                try:
                    ret = zlib.decompress(data)
                    if len(ret) > 0:
                        print(b2hex(ret))
                        print(decodebuf(ret))
                    else:
                        print(decodebuf(ret))
                except:
                    print(decodebuf(data))
        else:
            print(payload)
    else:
        print(message)


rdev = frida.get_usb_device()
session = rdev.attach("微信")  # 如果存在两个一样的进程名可以采用rdev.attach(pid)的方式
'''

'''
script = session.create_script(
    """
    //打印24数据
    var p_WeChat  = Module.findBaseAddress("WeChat");
    send("p_WeChat           @" + p_WeChat);

     if (ObjC.available)
    {
        try
        {
            var className = "iConsole";
            var funcName = "+ shouldLog:";
            var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
            Interceptor.attach(hook.implementation, {
             onEnter: function(args) {

              },
              onLeave: function(retval) {
                retval = 1;
              }
            });
        }catch(err)
        {
            console.log("[!] Exception: " + err.message);
        }

        try
        {
            var className = "iConsole";
            var funcName = "+ logWithLevel:module:errorCode:file:line:func:message:";
            var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
            Interceptor.attach(hook.implementation, {
             onEnter: function(args) {
                var urlStr = new ObjC.Object(args[8]).toString();
                console.log("[*] " + urlStr);
              },
              onLeave: function(retval) {

              }
            });
        }catch(err)
        {
            console.log("[!] Exception: " + err.message);
        }

        try
        {
            var className = "ProtobufEvent";
            var funcName = "- Pack:Host:sequenceId:";
            var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
            Interceptor.attach(hook.implementation, {
             onEnter: function(args) {
              console.log("[*] ProtobufEvent Pack:Host:sequenceId: in");
                this.packedBuffer = args[2];
              },
              onLeave: function(retval) {
                var ptrbodybyte = Memory.readPointer(this.packedBuffer);
                var ptrbodylen = this.packedBuffer.add(0x10);
                var bodylen = Memory.readUInt(ptrbodylen);
                if(bodylen>0x20)
                {
                    var array = Memory.readByteArray(ptrbodybyte, bodylen);
                    send("bodybyte",array);
                }
                console.log("[*] ProtobufEvent Pack:Host:sequenceId: out " + bodylen);
              }
            });
        }catch(err)
        {
            console.log("[!] Exception: " + err.message);
        }

        var className = "ProtobufEvent";
            var funcName = "- UnPack:headExtFlags:sequenceId:";
            var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
            Interceptor.attach(hook.implementation, {
              onEnter: function(args) {
              console.log("[*] ProtobufEvent UnPack:headExtFlags:sequenceId: in");
                this.packedBuffer = args[2];
                this.decryptBuffer = args[3];
                var ptrbodybyte = Memory.readPointer(this.packedBuffer);
                var ptrbodylen = this.packedBuffer.add(0x10);
                var bodylen = Memory.readUInt(ptrbodylen);
                if(bodylen>0x20)
                {
                    var array = Memory.readByteArray(ptrbodybyte, bodylen);
                    send("bodybyte",array);
                }
              },
              onLeave: function(retval) {
                var ptrbodybyte = Memory.readPointer(this.decryptBuffer);
                var ptrbodylen = this.decryptBuffer.add(0x10);
                var bodylen = Memory.readUInt(ptrbodylen);
               console.log("[*] ProtobufEvent UnPack:headExtFlags:sequenceId: out " + bodylen);

              }
            });

            var className = "CAESCrypt";
            var funcName = "+ fastAESEncryptWithKey:Data:";
            var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
            Interceptor.attach(hook.implementation, {
              onEnter: function(args) {
              console.log("[*] CAESCrypt fastAESEncryptWithKey in");
              var keydata = new ObjC.Object(args[2]);
              var array = Memory.readByteArray(keydata.bytes(), keydata.length());
              console.log("[*] fastAESEncryptWithKey AESKEY BUF DATA  #####" );
                 if(keydata.length() >0 )
                 {
                    send(hexdump(array, { length: keydata.length(), ansi: true }));
                 }
                 console.log("[*] fastAESEncryptWithKey DATA BUF #####" );
                 var bufferdata = new ObjC.Object(args[3]);

                 if(bufferdata.length() >0 )
                 {
                    var bufferarray = Memory.readByteArray(bufferdata.bytes(), bufferdata.length());
                    send("compressed",bufferarray);
                 }

              },
              onLeave: function(retval) {
               console.log("[*] CAESCrypt fastAESEncryptWithKey out ");
              }
            });


            var className = "CAESCrypt";
            var funcName = "+ fastAESDecryptWithKey:Data:";
            var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
            Interceptor.attach(hook.implementation, {
              onEnter: function(args) {
              console.log("[*] CAESCrypt fastAESDecryptWithKey in");
              var keydata = new ObjC.Object(args[2]);
              var array = Memory.readByteArray(keydata.bytes(), keydata.length());
              console.log("[*] fastAESDecryptWithKey AESKEY BUF DATA  #####" );
                 if(keydata.length() >0 )
                 {
                    send(hexdump(array, { length: keydata.length(), ansi: true }));
                 }


              },
              onLeave: function(retval) {
                 var bufferdata = new ObjC.Object(retval);
                 if(bufferdata.length() >0 )
                 {
                    var bufferarray = Memory.readByteArray(bufferdata.bytes(), bufferdata.length());
                    send("compressed",bufferarray);
                 }
               console.log("[*] CAESCrypt fastAESDecryptWithKey out ",new ObjC.Object(retval).$className);
              }
            });
    }
    else
    {
        console.log("Objective-C Runtime is not available!");
    }

    var p_mmcrypto_AesGcmEncryptWithCompress = p_WeChat.add(0x0E0C9204);
    console.log("[*] AesGcmEncryptWithCompress: " + p_mmcrypto_AesGcmEncryptWithCompress);

    var p_mmcrypto_AesGcmDecryptWithUncompress = p_WeChat.add(0x6439978);
    console.log("[*] AesGcmDecryptWithUncompress: " + p_mmcrypto_AesGcmDecryptWithUncompress);

    var p_mmcrypto_AesGcmEncryptWithCompress_outbuf = 0;
    Interceptor.attach(p_mmcrypto_AesGcmEncryptWithCompress, {
        onEnter: function(args) {
             console.log("[*] p_mmcrypto_AesGcmEncryptWithCompress in ");
        },
        onLeave: function (retval) {
            console.log("[*] p_mmcrypto_AesGcmEncryptWithCompress out " );
        }

    });    

    Interceptor.attach(p_mmcrypto_AesGcmDecryptWithUncompress, {
        onEnter: function(args) {
             console.log("[*] p_mmcrypto_AesGcmDecryptWithUncompress in ");
        },
        onLeave: function (retval) {
            console.log("[*] p_mmcrypto_AesGcmDecryptWithUncompress out " );
        }

    });    
    """)
script.on('message', on_message)
script.load()
sys.stdin.read()
