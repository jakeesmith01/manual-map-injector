# manual-map-injector
An injector that utilizes manual mapping techniques to attempt to inject .dll's in to game processes without the anticheat detecting it.

Usage:
- In main.cpp, line 3 set dllFilePath to the path to your .dll to be injected
- On the next line, set targetProc to the target process
- Ensure you're in release, and have the correct system architecture selected for your use-case.
- You will need to run VS as an admin to execute the program.

Disclaimer:
- I don't know what I'm doing! I put this together with nothing but willpower and google, and there's a great chance it is not safe to use with modern anticheats.
- To keep it simple: don't use this if you care about getting banned, and I'm not responsible if you do.
