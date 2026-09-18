import React, { useState } from 'react';
import { useNonceMutation } from '../hooks/useNonceMutation';
import UpdateTodoMutation from '../graphql/mutations/UpdateTodoMutation';
import DeleteTodoMutation from '../graphql/mutations/DeleteTodoMutation';

export interface Todo {
  id: string;
  title: string;
  description?: string | null;
  completed: boolean;
}

export interface TodoItemProps {
  todo: Todo;
  onChanged?: () => void;
}

export const TodoItem: React.FC<TodoItemProps> = ({ todo, onChanged }) => {
  const [updateTodo, isUpdating] = useNonceMutation(UpdateTodoMutation);
  const [deleteTodo, isDeleting] = useNonceMutation(DeleteTodoMutation);

  const [isEditing, setIsEditing] = useState(false);
  const [title, setTitle] = useState(todo.title);
  const [description, setDescription] = useState(todo.description ?? '');
  const [error, setError] = useState<string | null>(null);

  const busy = isUpdating || isDeleting;

  const run = async (action: () => Promise<unknown>): Promise<void> => {
    setError(null);
    try {
      await action();
      onChanged?.();
    } catch (mutationError) {
      setError(
        mutationError instanceof Error
          ? mutationError.message
          : 'Something went wrong. Please try again.'
      );
    }
  };

  const toggleCompleted = (): Promise<void> =>
    run(() =>
      updateTodo({
        id: todo.id,
        input: { completed: !todo.completed },
      })
    );

  const saveEdits = async (): Promise<void> => {
    await run(() =>
      updateTodo({
        id: todo.id,
        input: { title, description },
      })
    );
    setIsEditing(false);
  };

  const remove = (): Promise<void> => run(() => deleteTodo({ id: todo.id }));

  return (
    <li className="todo-item">
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      {isEditing ? (
        <div className="todo-item__edit">
          <label htmlFor={`title-${todo.id}`}>Title</label>
          <input
            id={`title-${todo.id}`}
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            disabled={busy}
          />

          <label htmlFor={`description-${todo.id}`}>Description</label>
          <input
            id={`description-${todo.id}`}
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            disabled={busy}
          />

          <button type="button" onClick={() => void saveEdits()} disabled={busy || !title.trim()}>
            {isUpdating ? 'Saving...' : 'Save'}
          </button>
          <button
            type="button"
            onClick={() => {
              setIsEditing(false);
              setTitle(todo.title);
              setDescription(todo.description ?? '');
            }}
            disabled={busy}
          >
            Cancel
          </button>
        </div>
      ) : (
        <div className="todo-item__view">
          <input
            type="checkbox"
            id={`completed-${todo.id}`}
            checked={todo.completed}
            onChange={() => void toggleCompleted()}
            disabled={busy}
          />
          <label htmlFor={`completed-${todo.id}`} className={todo.completed ? 'done' : ''}>
            {todo.title}
          </label>

          {todo.description && <p className="todo-item__description">{todo.description}</p>}

          <button type="button" onClick={() => setIsEditing(true)} disabled={busy}>
            Edit
          </button>
          <button type="button" onClick={() => void remove()} disabled={busy}>
            {isDeleting ? 'Deleting...' : 'Delete'}
          </button>
        </div>
      )}
    </li>
  );
};

export default TodoItem;
