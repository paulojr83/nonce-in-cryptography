import { graphql } from 'react-relay';

export const GetTodosQuery = graphql`
  query GetTodosQuery($first: Int, $after: String) {
    ...GetTodosQuery_todos @arguments(first: $first, after: $after)
  }
`;

export const TodosFragment = graphql`
  fragment GetTodosQuery_todos on Query
  @argumentDefinitions(
    first: { type: "Int", defaultValue: 10 }
    after: { type: "String" }
  )
  @refetchable(queryName: "TodosPaginationQuery") {
    todos(first: $first, after: $after) @connection(key: "GetTodosQuery_todos") {
      totalCount
      edges {
        cursor
        node {
          id
          title
          description
          completed
          createdAt
          updatedAt
        }
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
`;

export default GetTodosQuery;
