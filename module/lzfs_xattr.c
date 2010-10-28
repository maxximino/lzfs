#include <linux/fs.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/lzfs_inode.h>
#include <sys/lzfs_xattr.h>

int
lzfs_xattr_get(struct inode *inode, const char *name,
                    void *buffer, size_t size)
{
/*	char *tmp = "hello world";
	int error = 0;
	printk("name=%s, buffer=%p, buffer_size=%ld",
                   name, buffer, (long)size);	
	if(buffer) {
		memcpy(buffer, (void *)tmp, 12);
		error = 12;
	}
	return error;
*/
	
	vnode_t *vp;
        vnode_t *dvp;
        vnode_t *xvp;
        //vattr_t *vap;
        int err = 0;
        const struct cred *cred = get_current_cred();
        struct iovec iov = {
                .iov_base = buffer,
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
	//down_write(inode->xattr_sem);
	printk(" \nread file attr name is : %s\n", name); 
        dvp = LZFS_ITOV(inode);
	err = zfs_lookup(dvp, NULL, &vp, NULL, LOOKUP_XATTR, NULL,
                        (struct cred *) cred, NULL, NULL, NULL);
//	put_cred(cred);
        if(err) {
          //      up_write(inode->xattr_sem);
                return -err;
        }
	ASSERT(vp != NULL);
	err = zfs_lookup(vp, (char *) name, &xvp, NULL, 0, NULL,
                        (struct cred *) cred, NULL, NULL, NULL);
//	put_cred(cred); 
        if(err) {
            //    up_write(inode->xattr_sem);
                return -err;
        }
	err = zfs_read(xvp, &uio, 0, (cred_t *)cred, NULL);
        put_cred(cred);
        if(err) {
              //  up_write(inode->xattr_sem);
                return -err;
        }
	printk("read file buffer is : %s\n", (char *)buffer);
//	up_write(inode->xattr_sem);
	return err;
}



struct xattr_handler *lzfs_xattr_handlers[] = {
        &lzfs_xattr_user_handler,
//        &lzfs_xattr_trusted_handler,
#ifdef CONFIG_EXT2_FS_POSIX_ACL
  //      &lzfs_xattr_acl_access_handler,
    //    &lzfs_xattr_acl_default_handler,
#endif  
#ifdef CONFIG_EXT2_FS_SECURITY
      //  &lzfs_xattr_security_handler,
#endif          
        NULL
};


