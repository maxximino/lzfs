#include <linux/fs.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/lzfs_inode.h>
#include <sys/lzfs_xattr.h>
#include <linux/xattr.h>

static int
lzfs_xattr_user_get(struct inode *inode, const char *name,
                    void *buffer, size_t size)
{
	if(strcmp(name,"") == 0) {
		return -EINVAL;
	}

	return lzfs_xattr_get(inode, name, buffer, size);
}

static int      
lzfs_xattr_user_set(struct inode *inode, const char *name,
                    const void *value, size_t size, int flags)
{               

//	return -EOPNOTSUPP;	
	vnode_t *vp;
        vnode_t *dvp;
	vnode_t *xvp;
        vattr_t *vap;
        int err = 0;
        const struct cred *cred = get_current_cred();
	struct iovec iov = {
                .iov_base = (void *) value,
                .iov_len  = size,
        };

	uio_t uio = {
                .uio_iov     = &iov,
                .uio_resid   = size,
                .uio_iovcnt  = 1,
                .uio_loffset = (offset_t)0,
                .uio_limit   = MAXOFFSET_T,
                .uio_segflg  = UIO_SYSSPACE,
        };

	//err = checkname((char *)dentry->d_name.name);
	printk("name is : %s, value is : %s, size is :%ld", name, ( char *) value, (long)size);
        //if(err)
          //      return ((void * )-ENAMETOOLONG);
//        down_write(inode->xattr_sem);
	dvp = LZFS_ITOV(inode);
	err = zfs_lookup(dvp, NULL, &vp, NULL, LOOKUP_XATTR | CREATE_XATTR_DIR, NULL,
                        (struct cred *) cred, NULL, NULL, NULL);
      //  put_cred(cred);		
	printk("\n\n zfs_lookup complete \n\n");		
	if(err) {
//		up_write(inode->xattr_sem);
		return -err;
	}
	vap = kmalloc(sizeof(vattr_t), GFP_KERNEL);
        ASSERT(vap != NULL);

        memset(vap, 0, sizeof(vap));

        vap->va_type = VREG;
        vap->va_mode = 0644;
        vap->va_mask = AT_TYPE|AT_MODE;
        vap->va_uid = current_fsuid();
        vap->va_gid = current_fsgid();

	err = zfs_create(vp, (char *)name, vap, 0, 0644,
                         &xvp, (struct cred *)cred, 0, NULL, NULL);
	//put_cred(cred);
        kfree(vap);
	if(err) {
//		up_write(inode->xattr_sem);
		return -err;
	}
	err = zfs_write(xvp, &uio, 0, (cred_t *)cred, NULL);
        put_cred(cred);
	if(err) {
//		up_write(inode->xattr_sem);
		return -err;
	}
//	up_write(inode->xattr_sem);
	return err;
			
}

static size_t
lzfs_xattr_user_list(struct inode *inode, char *list, size_t list_size,
                     const char *name, size_t name_len)
{   
	return 0;            
}


struct xattr_handler lzfs_xattr_user_handler = {
        .prefix = XATTR_USER_PREFIX,
     .list   = lzfs_xattr_user_list,
        .get    = lzfs_xattr_user_get,
        .set    = lzfs_xattr_user_set,
};

