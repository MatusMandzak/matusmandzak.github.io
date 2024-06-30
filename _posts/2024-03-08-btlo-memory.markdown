---
layout: posts
title:  "BTLO Memory Dump - Ransomware"
date:   2024-03-08 19:30:00 +0100
---
*Challenge from BTLO labs focused on showing the basics of Volatility*

We are given a zip file containing a memory dump from infected computer to look into. To investigate we are going to use Volatility 3.

After downloading and installing Volatility, we can look at the first task:
![task1](/assets/images/Pasted image 20240308185214.png)

Running this command raises errors, due it's origin being from Vol 2. Therefore, we need to find the same command with same functionality that will be compatible with our current version.

Given the fact, documentation is often complicated to read, I rather went online to look for some cheatsheet on Volatility. Managed to find one that covers volatility 2 and 3 at the same time: https://blog.onfvp.com/post/volatility-cheatsheet/

Looking at the website I found command to gather info on memory dump file, so I ran it against the file we were given.
```
vol.py -f infected.mem windows.info
```

Which returned information about the system of memory file:

![info](/assets/images/Pasted image 20240308190002.png)

After that, I ran the command with the same semantic as the command given in the task:
```
vol -f infected.vmem windows.psscan
```

This returned a list of active processes at the time of memory snap:
![psscan](/assets/images/Pasted image 20240308190412.png)

Looking a processes we see multiple suspicious processes like: `@WanaDecryptor, or4qtckT.exe`.
Submitting `@WanaDecryptor` answers the first task successfully.

From the names we can assume the target malware is probably known malware Wannacry. Therefore we can confidently answer the sixth question:
![task6](/assets/images/Pasted image 20240308190802.png)

Now looking at the second question:
![tasl2](/assets/images/Pasted image 20240308190820.png)
We can utilize the used psscan, due to the fact it shows the PPID (parent process ID) of our suspicious process `@WanaDecryptor` -> `2732`

Looking for the process with PID same as the PPID of `@WanaDecryptor` we find its name: `or4qtckT.exe` answering the third question.
![task3](/assets/images/Pasted image 20240308191101.png)

The next task instructs us to look for other processes with the PID or PPID of PID of`or4qtcT.exe`. From psscan list we can see that it created 3 processes: `2x @WanaDecryptor; taskdl.exe`. The second is the answer for this task.
![task4](/assets/images/Pasted image 20240308191422.png)

The further task instructs us to find path do malicious file, where it was executed.
![task5](/assets/images/Pasted image 20240308191505.png)
Former psscan list won't help us with this task, hence we need to find another command that may help us. We can use volatility's cmdline, which displays the program command-line arguments.
```
vol -f infected.vmem windows.cmdline
```
Here we can see the absolute path of suspicious process:
![cmdline](/assets/images/Pasted image 20240308191938.png)

The next task we have answered previously so we move onto last one, where we are tasked to find the filename for the ransomware public key that was used to encrypt the private key.

Didn't quite gather what does the task mean, but we are looking for some keyfile.
One way to find this information is to look at the current open handles of our suspicious process and look for the handles with type `File`.

```
vol -f infected.vmem windows.handles --pid 2732
```

There are only three open handles with type of file and two of them aren't even harddisk files.
![handles](/assets/images/Pasted image 20240308192536.png)
We need the name of the key file: `00000000.eky`


Overall this was pretty simple challenge to get familiar with really basic functionality of Volatility. GIven I had no experience with using vol, I found it useful.
