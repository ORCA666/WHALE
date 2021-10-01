
# WHALE : A AES CRYPTOR

# USAGE:
All u have to do is to build "builder" project and run it according to ur arguments. the builder.exe will then build and modify the source code according to ur needs and build ur final encrypted binary file.

![image](https://user-images.githubusercontent.com/66519611/135586250-c3effa87-7322-4bd7-adbb-be5f111d0c0d.png)

# Arguments: 
 
[1] : `EvadeAllLoader` : Contains all the functions of other loaders listed below 

[2] : `EvadeDebuggerLoader` : Checks if the ppid isnt "explorer.exe" as in normal situations, if not it will not decode and exit

[3] : `EvadeSandBoxLoader` : Checks for hardware, history of usb mounted before, and the wifi connection of the target, if one of these situations are satisfied, it will not decode and exit

[4] : `PureLoader` : Do not add any checking for env method, it will decode and run directly 


# Example: BYPASSING KASPRESKEY AV WITH MIMIKATZ: 

![image](https://user-images.githubusercontent.com/66519611/135585830-885be123-3c49-40da-97cf-6e48524f97f9.png)


# BASED ON: https://github.com/frkngksl/Huan
