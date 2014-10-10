// $Id: node.c,v 1.7 2001/02/20 22:49:51 srp Exp $

// Copyright (c) 2000, 2001
//           Scott R Parish, OR  97119-9201.
//       All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer as
//    the first lines of this file unmodified.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY Scott R Parish ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL Scott R Parish BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "node.h"
#include <stdlib.h>
#include <signal.h>

struct node *get(struct node *n,int type) {
  while(n!=0) {
    if(n->type==type) {
      return n;
    }
    if(n->type>type)
      n=n->r;
    else
      n=n->l;
  } 
  return 0;
}

struct node *new(struct node *n, int type) {
  struct node *t=0;
  int i;

  while(n!=0) {
    if(n->type==type) {
      return 0;
    }
    if(n->type>type) {
      t=n;
      n=n->r;
    }
    else {
      t=n;
      n=n->l;
    }
  }
  signal(SIGWINCH,SIG_IGN);
  if(t->type>type) 
    n=t->r=malloc(sizeof(struct node));
  else 
    n=t->l=malloc(sizeof(struct node));
  n->r=0;
  n->l=0;
  n->type=type;
  n->count=0;
  n->size=0;
  for (i = 0; i < HISTORY_SIZE; i++)
    n->size_h[i] = 0;

  signal(SIGWINCH,change_screen_size);

  return n;
}

unsigned long long countsump(struct node *n) {
  unsigned long long a=0;
  if(!n)
    return 0;

  if(n->r)
    a=countsump(n->r);
  if(n->l)
    a+=countsump(n->l);

  return n->count + a;
}

unsigned long long countsums(struct node *n) {
  unsigned long long a=0;
  if(!n)
    return 0;

  if(n->r)
    a=countsums(n->r);
  if(n->l)
    a+=countsums(n->l);

  return n->size + a;
}

//get an array of pointers to the largest n nodes
void largestn(struct node *r, struct node *a[], int n, unsigned char sort_type) {
  int i,j;
  struct node *t, *v;

  if(!n) 
    return;
  for(i=0;i<n;i++) {
    if(!a[i] || ((sort_type=='p' && r->count > a[i]->count) || 
		 (sort_type=='s' && r->size > a[i]->size))) {
      t=a[i];
      a[i]=r;
      for(j=i+1; j<n && a[j]; j++) {
	v=a[j];
	a[j]=t;
	t=v;
      }
      if(j<n)
	a[j]=t;
      break;
    }
  }
  if(r->l) 
    largestn(r->l, a, n, sort_type);
  if(r->r)
    largestn(r->r, a, n, sort_type);
}

// clear the tree of nodes (reset the counter)
void ndelete(struct node *r) {
  if(r->l) {
    ndelete(r->l);
    free(r->l);
    r->l=0;
  }
  if(r->r) {
    ndelete(r->r);
    free(r->r);
    r->r=0;
  }
}
