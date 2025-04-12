# GGXrdVersionSelector

## Description

Allows you to change the used game patch version of Guilty Gear Xrd Rev2, which affects balance changes.

Available versions:

- **Latest Rev1/2** - this is just the game behaving normally.
- **25A** - a slightly older Rev2, I guess (I don't really know).
- **25** - the oldest available Rev2, I guess  (I don't really know).
- **Latest REV1** - you can get to this version without using this mod, by just selecting Rev1 in the game's own options.
- **20A** - a slightly older Rev1, I guess (I don't really know).
- **20** - the oldest bbscript files of Rev1, I guess (I don't really know).
- **20 pre 1.10** - this is the oldest bbscript files of Rev1 combined with an extra switch that affects input parsing and some framedata that was traced to changes in version 1.10.

*WARNING!*  
Using any version but `Latest Rev1/2` online will result in a desync if the other player also doesn't use the same version.

This mod works only with PC version 2211 of the game (seen on the bottom right of the main menu after launching the game).

## How to use

1. Go to Releases section on the right: <https://https://github.com/kkots/GGXrdVersionSelector/releases/latest>
2. Download the top .zip file from the latest release.
3. Extract that .zip file.
4. Launch Guilty Gear Xrd Rev2.
4. Launch the `GGXrdVersionSelector.exe`.
5. The field in the mod's window displays the current patch version used by the game. You may change it using that field. Make sure your friend also uses this mod and has selected the same version.
6. Restart the current match if it's currently ongoing in order for changes to fully take effect.
7. When you are done, you can reset the patch version back by selecting `Latest Rev1/2` which will let you play online with anyone without desyncs like normal.

## How to use on Linux

On Linux, Steam runs the Windows version of the game under Wine using Steam Proton. Use the `launch_GGXrdVersionSelector_linux.sh` script from the extracted .zip file to launch the Windows .exe executable of the mod under Wine, like so:

```bash
cd ?????????????????  # make sure to cd into the directory where the .sh script is
chmod u+x launch_GGXrdVersionSelector_linux.sh  # first, give yourself permission to launch the script
./launch_GGXrdVersionSelector_linux.sh  # launch the script. The .exe file must be in the current folder
```

The mod window should open. Next, follow the 'How to use' section.

## Notes

The game stops respecting your choice between Rev1 and Rev2 inside the game's own options if in the mod you select any option but `Latest Rev1/2`.

Replay mode will not be affected by this mod.

If you're an observer on a match that uses modded versions, you probably must also use that modded version in order to see the match correctly.

A match restart is required in order to fully apply a version change. Some changes that are related to general framedata like RCs and input parsing (due to 1.10 switch) may apply mid-match.

The change in version does not get saved after you exit the game. The mod has no patcher and must be used every time you reboot the game.
