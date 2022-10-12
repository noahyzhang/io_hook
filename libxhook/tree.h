#ifndef TREE_H_
#define TREE_H_

#define RB_ENTRY(type)                                                  \
struct {                                                                \
        struct type *rbe_left;          /* left element */              \
        struct type *rbe_right;         /* right element */             \
        struct type *rbe_parent;        /* parent element */            \
        int rbe_color;                  /* node color */                \
}

#endif  // TREE_H_
