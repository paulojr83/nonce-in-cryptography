import { graphql } from 'react-relay';

export const LogoutMutation = graphql`
  mutation LogoutMutation {
    logout {
      success
      message
    }
  }
`;

export default LogoutMutation;
