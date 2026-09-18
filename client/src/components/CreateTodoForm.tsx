import React, { useState } from 'react';
import { useNonceMutation } from '../hooks/useNonceMutation';
import CreateTodoMutation from '../graphql/mutations/CreateTodoMutation';

export interface CreateTodoFormProps {
  onCreated?: () => void;
}

export const CreateTodoForm: React.FC<CreateTodoFormProps> = ({ onCreated }) => {
  const [createTodo, isInFlight] = useNonceMutation(CreateTodoMutation);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleSubmit = async (event: React.FormEvent): Promise<void> => {
    event.preventDefault();
    setError(null);
    setSuccess(null);

    try {
      await createTodo({
        input: { title, description: description || null },
      });

      setTitle('');
      setDescription('');
      setSuccess('Todo added.');
      onCreated?.();
    } catch (mutationError) {
      setError(
        mutationError instanceof Error
          ? mutationError.message
          : 'Could not add the todo. Please try again.'
      );
    }
  };

  return (
    <form className="create-todo-form" onSubmit={handleSubmit}>
      <h2>Add a todo</h2>

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {success && (
        <p className="form-success" role="status">
          {success}
        </p>
      )}

      <label htmlFor="new-todo-title">Title</label>
      <input
        id="new-todo-title"
        value={title}
        onChange={(event) => setTitle(event.target.value)}
        disabled={isInFlight}
        required
      />

      <label htmlFor="new-todo-description">Description</label>
      <input
        id="new-todo-description"
        value={description}
        onChange={(event) => setDescription(event.target.value)}
        disabled={isInFlight}
      />

      <button type="submit" disabled={isInFlight || !title.trim()}>
        {isInFlight ? 'Adding...' : 'Add todo'}
      </button>
    </form>
  );
};

export default CreateTodoForm;
