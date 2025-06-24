This is a POC for a (now) security irrelevant bug I found in the grub affs filesystem parser.
After [this](https://lists.nongnu.org/archive/html/grub-devel/2025-02/msg00073.html) patch, many filesystems are no longer vectors for compromising secure boot.

In affs.c, line 412:
```c
  /* Create the directory entries for `.' and `..'.  */
  node = orig_node = grub_zalloc (sizeof (*node));
  if (!node)
    return 1;

  *node = *dir;
  if (hook (".", GRUB_FSHELP_DIR, node, hook_data))
    return 1;
  if (dir->parent)
    {
      *node = *dir->parent;
      if (hook ("..", GRUB_FSHELP_DIR, node, hook_data))
return 1;
    }
```

Inside `grub_affs_iterate_dir`, `node` will be freed inside `hook` if the path does not match ".". If the hook returns 0, then when returning  to `grub_affs_iterate_dir` we eventually reach line 472, where `node` will be freed again -- at this point `node` and `orig_node` have the same value. Another potential path for this is entering the function and after returning from `grub_affs_create_node` it will also be free'd on line 462. Both of these stem from the fact that both node and orig_node still have the same value assigned on line 413 which can be freed when going into the hook logic.

I've attached a reproducer affs filesystem file and a simple grub script to be run inside grub-emu which demonstrates the bug, all that's needed is to:
```
grub-emu -d <path to grub.cfg dir>
```
You may also have to change the path inside grub.cfg to point to the affs filesystem file. When done correctly you should observe a double free error.


