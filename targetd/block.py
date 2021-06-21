# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Copyright 2012-2013, Andy Grover <agrover@redhat.com>
#
# Routines to export block devices over iscsi.

from rtslib_fb import (
    Target,
    TPG,
    NodeACL,
    FabricModule,
    BlockStorageObject,
    NetworkPortal,
    MappedLUN,
    RTSLibError,
    RTSLibNotInCFS,
    NodeACLGroup,
)

from targetd.backends import zfs
from targetd.main import TargetdError
from targetd.utils import ignored, name_check

MAX_LUN = 256


def set_portal_addresses(tpg):
    for a in addresses:
        NetworkPortal(tpg, a)


pool_modules = {"zfs": zfs}
target_name = ""
addresses = []


def pool_module(pool_name):
    for modname, mod in pool_modules.items():
        if mod.has_pool(pool_name):
            return mod
    raise TargetdError(TargetdError.INVALID_POOL, "Invalid pool (%s)" % pool_name)


def udev_path_module(udev_path):
    for modname, mod in pool_modules.items():
        if mod.has_udev_path(udev_path):
            return mod
    raise TargetdError(
        TargetdError.INVALID_POOL, "Pool not found by udev path (%s)" % udev_path
    )


def so_name_module(so_name):
    for modname, mod in pool_modules.items():
        if mod.has_so_name(so_name):
            return mod
    raise TargetdError(
        TargetdError.INVALID_POOL, "Pool not found by storage object (%s)" % so_name
    )


#
# config_dict must include block_pools and target_name or we blow up
#
def initialize(config_dict):
    pools = dict()
    pools["zfs"] = list(config_dict["zfs_block_pools"])

    global target_name
    target_name = config_dict["target_name"]

    global addresses
    addresses = config_dict["portal_addresses"]

    # initialize and check both pools
    for modname, mod in pool_modules.items():
        mod.initialize(config_dict, pools[modname])

    return dict(
        vol_list=volumes,
        vol_create=create,
        vol_destroy=destroy,
        vol_copy=copy,
        vol_resize=resize,
        export_list=export_list,
        export_create=export_create,
        export_destroy=export_destroy,
        initiator_set_auth=initiator_set_auth,
        initiator_list=initiator_list,
    )


def volumes(req, pool):
    return pool_module(pool).volumes(req, pool)


def check_vol_exists(req, pool, name):
    mod = pool_module(pool)
    if any(v["name"] == name for v in mod.volumes(req, pool)):
        return True
    return False


def create(req, pool, name, size):
    mod = pool_module(pool)
    # Check to ensure that we don't have a volume with this name already,
    # lvm/zfs will fail if we try to create a LV/dataset with a duplicate name
    if check_vol_exists(req, pool, name):
        raise TargetdError(TargetdError.NAME_CONFLICT, "Volume with that name exists")
    mod.create(req, pool, name, size)


def get_so_name(pool, volname):
    return pool_module(pool).get_so_name(pool, volname)


def destroy(req, pool, name):
    mod = pool_module(pool)
    if not check_vol_exists(req, pool, name):
        raise TargetdError(
            TargetdError.NOT_FOUND_VOLUME,
            "Volume %s not found in pool %s" % (name, pool),
        )

    with ignored(RTSLibNotInCFS):
        fm = FabricModule("iscsi")
        t = Target(fm, target_name, mode="lookup")
        tpg = TPG(t, 1, mode="lookup")

        so_name = get_so_name(pool, name)

        if so_name in (lun.storage_object.name for lun in tpg.luns):
            raise TargetdError(
                TargetdError.VOLUME_MASKED,
                "Volume '%s' cannot be " "removed while exported" % name,
            )

    mod.destroy(req, pool, name)


def copy(req, pool, vol_orig, vol_new, size=None, timeout=10):
    mod = pool_module(pool)
    if not check_vol_exists(req, pool, vol_orig):
        raise TargetdError(
            TargetdError.NOT_FOUND_VOLUME,
            "Volume %s not found in pool %s" % (vol_orig, pool),
        )

    if size is not None:
        for v in mod.volumes(req, pool):
            if v["name"] == vol_orig and v["size"] >= size:
                raise TargetdError(
                    TargetdError.INVALID_ARGUMENT,
                    "Size %d need a larger than size in original volume %s in pool %s"
                    % (size, vol_orig, pool),
                )

    mod.copy(req, pool, vol_orig, vol_new, size, timeout)


def resize(req, pool, name, size):
    mod = pool_module(pool)
    if not check_vol_exists(req, pool, name):
        raise TargetdError(
            TargetdError.NOT_FOUND_VOLUME,
            "Volume %s not found in pool %s" % (name, pool),
        )

    for v in mod.volumes(req, pool):
        if v["name"] == name and v["size"] >= size:
            raise TargetdError(
                TargetdError.INVALID_ARGUMENT,
                "Size %d need a larger than size in original volume %s in pool %s"
                % (size, name, pool),
            )

    mod.resize(req, pool, name, size)


def export_list(req):
    try:
        fm = FabricModule("iscsi")
        t = Target(fm, target_name, mode="lookup")
        tpg = TPG(t, 1, mode="lookup")
    except RTSLibNotInCFS:
        return []

    exports = []
    for na in tpg.node_acls:
        for mlun in na.mapped_luns:
            mod = udev_path_module(mlun.tpg_lun.storage_object.udev_path)
            mlun_pool, mlun_name = mod.split_udev_path(
                mlun.tpg_lun.storage_object.udev_path
            )
            vinfo = mod.vol_info(mod.dev2pool_name(mlun_pool), mlun_name)
            exports.append(
                dict(
                    initiator_wwn=na.node_wwn,
                    lun=mlun.mapped_lun,
                    vol_name=mlun_name,
                    pool=mod.dev2pool_name(mlun_pool),
                    vol_uuid=vinfo.uuid,
                    vol_size=vinfo.size,
                )
            )
    return exports


def export_create(req, pool, vol, initiator_wwn, lun):
    fm = FabricModule("iscsi")
    t = Target(fm, target_name)
    tpg = TPG(t, 1)
    tpg.enable = True
    tpg.set_attribute("authentication", "0")

    set_portal_addresses(tpg)

    na = NodeACL(tpg, initiator_wwn)

    tpg_lun = _tpg_lun_of(tpg, pool, vol)

    # only add mapped lun if it doesn't exist
    for tmp_mlun in tpg_lun.mapped_luns:
        if tmp_mlun.mapped_lun == lun and tmp_mlun.parent_nodeacl == na:
            break
    else:
        MappedLUN(na, lun, tpg_lun)



def export_destroy(req, pool, vol, initiator_wwn):
    mod = pool_module(pool)
    fm = FabricModule("iscsi")
    t = Target(fm, target_name)
    tpg = TPG(t, 1)
    na = NodeACL(tpg, initiator_wwn)

    pool_dev_name = mod.pool2dev_name(pool)

    for mlun in na.mapped_luns:
        # all SOs are Block so we can access udev_path safely
        if mod.has_udev_path(mlun.tpg_lun.storage_object.udev_path):
            mlun_vg, mlun_name = mod.split_udev_path(
                mlun.tpg_lun.storage_object.udev_path
            )

            if mlun_vg == pool_dev_name and mlun_name == vol:
                tpg_lun = mlun.tpg_lun
                mlun.delete()
                # be tidy and delete unused tpg lun mappings?
                if not any(tpg_lun.mapped_luns):
                    so = tpg_lun.storage_object
                    tpg_lun.delete()
                    so.delete()
                break
    else:
        raise TargetdError(
            TargetdError.NOT_FOUND_VOLUME_EXPORT,
            "Volume '%s' not found in %s exports" % (vol, initiator_wwn),
        )

    # Clean up tree if branch has no leaf
    if not any(na.mapped_luns):
        na.delete()
        if not any(tpg.node_acls):
            tpg.delete()
            if not any(t.tpgs):
                t.delete()



def initiator_set_auth(req, initiator_wwn, in_user, in_pass, out_user, out_pass):
    # TODO: re-implement
    pass

    # fm = FabricModule("iscsi")
    # t = Target(fm, target_name)
    # tpg = TPG(t, 1)
    # na = NodeACL(tpg, initiator_wwn)

    # if not in_user or not in_pass:
    #     # rtslib treats '' as its NULL value for these
    #     in_user = in_pass = ""

    # if not out_user or not out_pass:
    #     out_user = out_pass = ""

    # na.chap_userid = in_user
    # na.chap_password = in_pass

    # na.chap_mutual_userid = out_user
    # na.chap_mutual_password = out_pass



def block_pools(req):
    results = []

    for modname, mod in pool_modules.items():
        results += mod.block_pools(req)

    return results



def _tpg_lun_of(tpg, pool_name, vol_name):
    """
    Return a object of LUN for given pool and volume.
    If not exist, create one.
    """
    mod = pool_module(pool_name)
    # get wwn of volume so LIO can export as vpd83 info
    vol_serial = mod.vol_info(pool_name, vol_name).uuid

    # only add new SO if it doesn't exist
    # so.name concats pool & vol names separated by ':'
    so_name = mod.get_so_name(pool_name, vol_name)
    try:
        so = BlockStorageObject(so_name)
    except RTSLibError:
        so = BlockStorageObject(so_name, dev=mod.get_dev_path(pool_name, vol_name))
        so.wwn = vol_serial

    # only add tpg lun if it doesn't exist
    for tmp_lun in tpg.luns:
        if (
            tmp_lun.storage_object.name == so.name
            and tmp_lun.storage_object.plugin == "block"
        ):
            return tmp_lun
    else:
        return LUN(tpg, storage_object=so)
