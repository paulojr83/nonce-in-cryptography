import React, { Suspense } from 'react';
import { useLazyLoadQuery, usePaginationFragment } from 'react-relay';
import GetTodosQuery, { TodosFragment } from '../graphql/queries/GetTodosQuery';
import TodoItem, { type Todo } from './TodoItem';

export const PAGE_SIZE = 10;

interface Connection {
  todos: {
    totalCount: number;
    edges: ReadonlyArray<{ cursor: string; node: Todo } | null> | null;
  } | null;
}

const TodoListContent: React.FC<{ queryRef: unknown; onChanged?: () => void }> = ({
  queryRef,
  onChanged,
}) => {
  const { data, loadNext, hasNext, isLoadingNext } = usePaginationFragment(
    TodosFragment,
    queryRef as never
  );

  const connection = (data as unknown as Connection)?.todos;
  const edges = connection?.edges ?? [];

  if (edges.length === 0) {
    return <p className="todo-list__empty">No todos yet. Add your first one above.</p>;
  }

  return (
    <div className="todo-list">
      <p className="todo-list__count">{connection?.totalCount ?? edges.length} todo(s)</p>

      <ul>
        {edges.map((edge) =>
          edge?.node ? (
            <TodoItem key={edge.node.id} todo={edge.node} onChanged={onChanged} />
          ) : null
        )}
      </ul>

      {hasNext && (
        <button
          type="button"
          onClick={() => loadNext(PAGE_SIZE)}
          disabled={isLoadingNext}
        >
          {isLoadingNext ? 'Loading...' : 'Load more'}
        </button>
      )}
    </div>
  );
};

export interface TodoListProps {
  refreshKey?: number;
  onChanged?: () => void;
}

const TodoListQuery: React.FC<TodoListProps> = ({ refreshKey = 0, onChanged }) => {
  const data = useLazyLoadQuery(
    GetTodosQuery,
    { first: PAGE_SIZE },
    { fetchKey: refreshKey, fetchPolicy: 'store-and-network' }
  );

  return <TodoListContent queryRef={data} onChanged={onChanged} />;
};

export const TodoList: React.FC<TodoListProps> = (props) => (
  <Suspense fallback={<p className="todo-list__loading">Loading todos...</p>}>
    <TodoListQuery {...props} />
  </Suspense>
);

export default TodoList;
