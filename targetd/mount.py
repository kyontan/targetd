import subprocess

class Mount(object):
    """
    Abstraction around mount
    """

    @staticmethod
    def mounted_filesystems(type):
        """
        Get all currently mounted filesystems typed type
        :return: generator of mount info array of tuple
        """
        def mounted_filesystems():
            proc = subprocess.Popen(['mount','-t', 'zfs'],stdout=subprocess.PIPE)
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                # line is like "alice on /alice (zfs, local, nfsv4acls)""
                words = line.decode().split(" ")
                yield (words[2], words[0]) # (mountpoint, zfs path)
