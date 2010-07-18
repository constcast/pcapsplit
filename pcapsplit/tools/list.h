//  Copyright (C) 2010 Lothar Braun <lothar@lobraun.de>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifndef _LIST_H_
#define _LIST_H_

struct list_element_t {
	void* data;
	struct list_element_t* prev;
	struct list_element_t* next;
};

typedef struct {
	struct list_element_t* head;
	struct list_element_t* tail;
} list_t;

list_t* list_create();
inline int list_destroy(list_t* list);

inline struct list_element_t* list_front(list_t* list);
inline struct list_element_t* list_back(list_t* list);

inline int list_push_front(list_t* list, struct list_element_t* element);
inline int list_push_back(list_t* list, struct list_element_t* element);

inline struct list_element_t* list_pop_front(list_t* list);
inline struct list_element_t* list_pop_back(list_t* list);

#endif
