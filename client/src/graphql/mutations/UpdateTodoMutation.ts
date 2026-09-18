import { graphql } from 'react-relay';

export const UpdateTodoMutation = graphql`
  mutation UpdateTodoMutation($id: ID!, $input: UpdateTodoInput!) {
    updateTodo(id: $id, input: $input) {
      todo {
        id
        title
        description
        completed
        createdAt
        updatedAt
      }
      nonce
    }
  }
`;

export default UpdateTodoMutation;
