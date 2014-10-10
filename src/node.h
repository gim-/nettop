// $Id: node.h,v 1.7 2001/02/20 22:39:04 srp Exp $

#ifndef NODE_H
#define NODE_H

// how many history sizes to keep (effects size of each node as well as sums_h)
#define HISTORY_SIZE 10 

struct node {
  struct node *l, *r;
  int type;
  unsigned int count;				//how many packets
  unsigned long long size;			//total size from all packets
  unsigned long long size_h[HISTORY_SIZE];	//history of last sizes
};

extern void change_screen_size();

struct node *get(struct node *n, int type);
struct node *new(struct node *n, int type);
unsigned long long countsump(struct node *n);
unsigned long long countsums(struct node *n);

//get an array of pointers to the largest n nodes
void largestn(struct node *r, struct node *a[], int n, unsigned char sort_type);

//delete the tree of nodes
void ndelete(struct node *r);


#endif
