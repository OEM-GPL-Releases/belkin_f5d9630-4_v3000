#ifdef __KERNEL__

typedef struct kobject *kobj_probe_t(dev_t, int *, void *);
struct kobj_map;

int kobj_map(struct kobj_map *, dev_t, unsigned long, struct module *,
	     kobj_probe_t *, int (*)(dev_t, void *), void *);
void kobj_unmap(struct kobj_map *, dev_t, unsigned long);
struct kobject *kobj_lookup(struct kobj_map *, dev_t, int *);
struct kobj_map *kobj_map_init(kobj_probe_t *, struct subsystem *);

#endif
