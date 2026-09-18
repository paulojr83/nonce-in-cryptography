import { graphql } from 'react-relay';

export const DeleteTodoMutation = graphql`
  mutation DeleteTodoMutation($id: ID!) {
    deleteTodo(id: $id) {
      todo {
        id
      }
      nonce
    }
  }
`;

export default DeleteTodoMutation;
