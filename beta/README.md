# encryption using a onetime pad concept
The Icmpdoor class was created so that users have the ability to encrypt their transmissions.  In doing this a secondary effect of verification is introduced in that both machines will silently discard any packet which is not encrypted properly, thus reducing the chance of inadvertent commands being ran on the machine or false info presented back to the user.

Within the class are 5 lines which have default parameters; search for ## CHANGE ME.  These objects can be modified at runtime by way of a parameter being passed or by the user modifying the code prior to running.  The recommended way is to modify the lines of code as this will reduce the forensic footprint from a logging perspective on the target machine.

The remote removal option is activated by entering ```___otp___```.  Invoking this will stop the remote listener.  If the filename on the remote side is otp.py the file is removed.

Example usage:
- Ensure the libraries listed in requirements.txt are installed via ```python3 -m pip install -r requirements.txt```
- Create a copy of `icmpdoor.py` called `otp.py`
- Run ```python3 ./icmpdoor.py -g```
- Enter a password
- Modify ## CHANGE ME lines as wanted
- Copy ```otp.py``` to the target machine
- Run ```python3 ./otp.py``` from the target machine
- Run ```python3 ./otp.py -m server``` from the Command and Control host
