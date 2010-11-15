#include <linux/fs.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/lzfs_inode.h>
#include <sys/lzfs_xattr.h>
#include <linux/xattr.h>

int
lzfs_xattr_get(struct inode *inode, const char *name,
                    void *buffer, size_t size)
{
	struct inode *xinode = NULL;	
	vnode_t *vp;
	vnode_t *dvp;
	vnode_t *xvp;
	int err = 0;
	const struct cred *cred = get_current_cred();
	struct iovec iov;
	uio_t uio;
        
	dvp = LZFS_ITOV(inode);
	err = zfs_lookup(dvp, NULL, &vp, NULL, LOOKUP_XATTR, NULL,
			(struct cred *) cred, NULL, NULL, NULL);
	if(err) {
		return -err;
        }
	ASSERT(vp != NULL);
	
	err = zfs_lookup(vp, (char *) name, &xvp, NULL, 0, NULL,
	(struct cred *) cred, NULL, NULL, NULL);
	if(err) {
		return -err;
	}
	xinode = LZFS_VTOI(xvp);
	if(!size) {
		return ((int) xinode->i_size); 
	}
	iov.iov_base = buffer;
	iov.iov_len  = size;
	uio.uio_iov     = &iov;
	uio.uio_resid   = size;
	uio.uio_iovcnt  = 1;
	uio.uio_loffset = (offset_t)0;
	uio.uio_segflg  = UIO_SYSSPACE;

	err = zfs_read(xvp, &uio, 0, (cred_t *)cred, NULL);
	put_cred(cred);
	if(err) {
		return -err;
	}
	
	return size - uio.uio_resid;
}

#define for_each_xattr_handler(handlers, handler)               \
		for ((handler) = *(handlers)++;                 \
			(handler) != NULL;                      \
			(handler) = *(handlers)++)


static inline struct xattr_handler *
find_xattr_handler_prefix(struct xattr_handler **handlers,
                           const char *name)
{
	struct xattr_handler *ea_handler;

	if (!handlers) {
		return NULL;
	}
	for_each_xattr_handler(handlers, ea_handler) {
		if (strncmp(ea_handler->prefix, name, 
			strlen(ea_handler->prefix)) == 0)
                        break;
        }
        return ea_handler;
}



struct listxattr_buf {
	size_t size;
	size_t pos;
	char *buf;
	struct inode *inode;
};


static int listxattr_filler(void *buf, const char *name, int namelen,
                            loff_t offset, u64 ino, unsigned int d_type)
{
	
	struct listxattr_buf *b = (struct listxattr_buf *)buf;
	size_t size = 0;
	
	if (name[0] != '.' ||
		(namelen != 1 && (name[1] != '.' || namelen != 2))) {
			struct xattr_handler *handler;
			handler = find_xattr_handler_prefix(
					b->inode->i_sb->s_xattr,
					"user.");
			if (!handler)
				return 0;
			if (b->buf) {
				size = handler->list(b->inode, b->buf + b->pos,
                                         b->size, name, namelen);
				if (size > b->size)
					return -ERANGE;
			} else {
				size = handler->list(b->inode, NULL, 
						0, name, namelen);
			}
	}
	b->pos += size;
        return 0;
}


ssize_t
lzfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	vnode_t *dvp;
	vnode_t *vp; /* xattr dir vnode pointer */
	int err = 0, eof;
	const struct cred *cred = get_current_cred();
	loff_t pos = 0;

	struct listxattr_buf buf = {
		.inode = dentry->d_inode,
		.buf = buffer,
		.size = buffer ? size : 0,
	};

	dvp = LZFS_ITOV(dentry->d_inode);
	err = zfs_lookup(dvp, NULL, &vp, NULL, LOOKUP_XATTR, NULL,
			(struct cred *) cred, NULL, NULL, NULL);
	if(err) {
		return -err;
	}
	ASSERT(vp != NULL);

	if(!size)
		return (LZFS_VTOI(vp))->i_size;
	err = zfs_readdir(vp, (void *)&buf, NULL, &eof, NULL, 0, 
			listxattr_filler, &pos);
	if(err)
		return -err;	
	else
		err = buf.pos;
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

