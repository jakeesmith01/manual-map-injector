# manual-map-injector
An injector that utilizes manual mapping techniques to attempt to inject .dll's in to game processes without the anticheat detecting it.

Usage:
- In main.cpp, line 3 set dllFilePath to the path of your .dll to be injected
- On the next line, set targetProc to the target process
- Ensure you're in release, and have the correct system architecture selected for your use-case.
- You will need to run VS as an admin to execute the program.

Disclaimer:
- This project was purely a learning opportunity for me. While I had success injecting dlls to games while evading the anticheat, I cannot gurantee that this will remain the same or will work at all for you. Each anticheat is different, and I was using a fairly lenient, non kernel anti cheat for testing.
- To keep it simple: don't use this if you care about getting banned, and I'm not responsible if you do.
