import { graphql } from 'react-relay';

export const CreateTodoMutation = graphql`
  mutation CreateTodoMutation($input: CreateTodoInput!) {
    createTodo(input: $input) {
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

export default CreateTodoMutation;
